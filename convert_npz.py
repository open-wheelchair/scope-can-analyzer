#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only

from enum import Enum
import functools
import argparse
from pathlib import Path
import datetime

import numpy as np
from sklearn.cluster import KMeans
import scapy.layers.can
import pcapng.blocks as blocks
from pcapng import FileWriter


DESCRIPTION = """Converts .npz file containing differential scope data to handier formats to work with.

Supported out formats:

- pcapng SocketCAN (direction encoded as interface)
- candump -l format (direction encoded as interface)
"""



def extension_validator(*extensions):
    def validate(value):
        path = Path(value)
        if path.suffix.lower() not in extensions:
            allowed = ", ".join(extensions)
            raise argparse.ArgumentTypeError(
                f"{value!r} must have one of these extensions: {allowed}"
            )
        return value

    return validate


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=DESCRIPTION)

parser.add_argument(
    "--bitrate",
    type=int,
    default=125000,
    help="CAN bitrate in bits/s (default: 125000)",
)

parser.add_argument(
    "infile",
    help="Input .npz capture file",
)
parser.add_argument(
    "--pcapng",
    type=extension_validator(".pcapng"),
    help="Optional PCAPNG output path",
)

parser.add_argument(
    "--candump",
    type=extension_validator(".log"),
    help="Optional candump output path",
)


args = parser.parse_args()

if not any((args.pcapng, args.candump)):
    parser.error("At least one output file format must be specified (--pcapng or --candump)")


in_objects = np.load(args.infile)

SAMPLE_RATE = in_objects.get('sample_rate', 10_000_000)
CAN_BITRATE = args.bitrate
SAMPLES_PER_CAN_BIT = (SAMPLE_RATE // CAN_BITRATE)
METADATA = str(in_objects.get('metadata', '')).strip()

print("Capture metadata:")
print(METADATA)

selected_1, selected_2 = in_objects['scaled_ch_1'], in_objects['scaled_ch_2']

print("Figuring out voltage thresholds")
kmeans = KMeans(n_clusters=2, random_state=0).fit(selected_1.reshape(-1, 1))
THRESHOLD_VOLTAGE= float(kmeans.cluster_centers_.max() + kmeans.cluster_centers_.min()) / 2

kmeans = KMeans(n_clusters=2, random_state=0).fit((selected_1 - selected_2).reshape(-1, 1))
THRESHOLD_VOLTAGE_DIFFERENCE = float(kmeans.cluster_centers_.max() + kmeans.cluster_centers_.min()) / 2

print("Demodulating CAN")

class DemodFSM(Enum):
    IDLE = 0
    SAMPLE = 1
    EDGE_FIND = 2
    FINISH = 3

packets = []

offsets_shared = tuple([
    ('SOF', 1),
    ('ID', 11),
    ('RTR', 1),
    ('IDE', 1),
])

offsets_11 = tuple([
    ('SOF', 1),
    ('ID', 11),
    ('RTR', 1),
    ('IDE', 1),
    ('r0', 1),
    ('DLC', 4),
    ('DATA', None),
    ('CRC', 15),
    ('CRC_DELIM', 1),
    ('ACK_SLOT', 1),
    ('ACK_DELIM', 1),
    ('EOF', 7),
    ('END', None)
])

offsets_29 = tuple([
    ('SOF', 1),
    ('ID_A', 11),
    ('SRR', 1),
    ('IDE', 1),
    ('ID_B', 18),
    ('RTR', 1),
    ('r0,r1', 2),
    ('DLC', 4),
    ('DATA', None),
    ('CRC', 15),
    ('CRC_DELIM', 1),
    ('ACK_SLOT', 1),
    ('ACK_DELIM', 1),
    ('EOF', 7),
    ('END', None)
])

@functools.cache
def get_offset(table, search_key, data_len=None):
    current_offset = 0
    for key, value in table:
        if key == search_key:
            return current_offset
        if key == 'DATA':
            current_offset += data_len
        else:
            current_offset += value
    raise KeyError(f'{search_key} not found')

def find_key_by_offset(table, search_offset, data_len=None):
    current_offset = 0
    for key, value in table:
        if key == 'DATA':
            current_offset += data_len
        else:
            current_offset += value
        if current_offset >= search_offset:
            return key
    raise KeyError(f'{search_offset} too big')

def map_bits_to_table(table, bits, data_len):
    expected_len = sum(length for name, length in table if length is not None) + data_len
    assert len(bits) == expected_len, f'Have: {len(bits)}, expected {expected_len}'
    fields = {}
    current_offset = 0
    for keyname, length in table:
        if keyname == 'DATA':
            length = data_len
        if keyname == 'END':
            return fields
        fields[keyname] = int(''.join(str(bit) for bit in bits[current_offset:current_offset+length]), 2) if length else None
        current_offset += length

class Packet:
    def __init__(self, start_time):
        self.start_time = start_time
        # bits before correcting for bit stuffing
        self.bits_raw = []
        # bits after processing bit stuffing
        self.bits = []
        self.dlc = None
        self.data_len = None
        self.rtr = None
        self.is_extended_frame = None
        self.do_bit_unstuffing = True
        self.mapped = None
        self.error = None
        self.sender = None

    def __repr__(self):
        if self.error is not None:
            return f'{self.error} error'
        if self.mapped is not None:
            fields = {name: bin(value) if value is not None else value for name, value in self.mapped.items()}
            return f'{fields}'

    def as_scapy(self):
        if self.error:
            # TODO try to recover some data if able
            return scapy.layers.can.CAN(
                            identifier = 0,
                            data = bytes(),
                            flags = 'error'
                        )
        else:
            flags = set()
            if self.rtr:
                flags.add('remote_transmission_request')
            if self.is_extended_frame:
                flags.add('extended')
            return scapy.layers.can.CAN(
                            identifier = self.can_id(),
                            data = self.data(),
                            flags = '+'.join(flags)
                        )



    def can_id(self):
        assert self.mapped and self.is_extended_frame in (True, False)
        if self.is_extended_frame:
            return self.mapped['ID_A'] << 18 | self.mapped['ID_B']
        else:
            return self.mapped['ID']

    def data(self):
        assert self.mapped and self.is_extended_frame in (True, False)
        if self.mapped['DATA'] is None:
            return b''
        return self.mapped['DATA'].to_bytes(length=self.data_len//8)

    def calculate_crc(self):
        search_table = {
            None: offsets_shared,
            False: offsets_11,
            True: offsets_29
        }[self.is_extended_frame]
        crc_offset = get_offset(search_table, "CRC", data_len=self.data_len)
        assert len(self.bits) >= crc_offset
        crc_shift_reg = 0
        for bit in self.bits[:crc_offset]:
            crc_nxt = bit ^ ((crc_shift_reg >> 14) & 0b1)
            crc_shift_reg = (crc_shift_reg << 1) & 0x7fff
            if crc_nxt:
                crc_shift_reg = crc_shift_reg ^ 0x4599
        return crc_shift_reg

    # returns True if the packet is finished
    def add_bit(self, bit: bool, level_1: float, level_2: float, sample_idx: int):
        if self.do_bit_unstuffing and bit:
            # someone is pulling the line high, so we can measure the voltage difference
            self.voltage_difference = level_1 - level_2

        # logic-level high (~4V) == dominant == 0 bit
        # logic-level low (~0V) == recessive == 1 bit
        bit = int(not bit)

        self.bits_raw.append(bit)


        last_six_bits = self.bits_raw[-6:]
        if len(last_six_bits) == 6 and sum(last_six_bits[:5]) in (0, 5):
            # 5 consecutive bits, so next bit determines if this is an active error or stuffing bit
            if last_six_bits[0] == last_six_bits[-1]: # error = 6 consecutive bits
                if last_six_bits[-1] == 0:
                    search_table = {
                        None: offsets_shared,
                        False: offsets_11,
                        True: offsets_29
                    }[self.is_extended_frame]
                    self.error = f'active error at {find_key_by_offset(search_table, len(self.bits), data_len=self.data_len)}'
                    return True
                elif self.do_bit_unstuffing:
                    self.error = 'passive'
                    return True
            elif self.do_bit_unstuffing:
                # this is a stuffing bit, don't append it to real bits
                return False
        self.bits.append(bit)

        if len(self.bits) < 1 + get_offset(offsets_shared, 'IDE'):
            return False
        if len(self.bits) == 1 + get_offset(offsets_shared, 'IDE'):
            self.is_extended_frame = self.bits[get_offset(offsets_shared, 'IDE')]
            return False

        packet_offsets = offsets_29 if self.is_extended_frame else offsets_11
        dlc_offset = get_offset(packet_offsets, 'DLC')
        if len(self.bits) < 4 + dlc_offset:
            return False
        if len(self.bits) == 4 + dlc_offset:
            self.dlc = int(''.join(str(bit) for bit in self.bits[dlc_offset:dlc_offset+4]), 2)
            self.rtr = self.bits[get_offset(packet_offsets, 'RTR')]
            self.data_len = 0 if self.rtr else self.dlc * 8

        if len(self.bits) < get_offset(packet_offsets, 'CRC_DELIM', data_len=self.data_len):
            return False
        if len(self.bits) == get_offset(packet_offsets, 'CRC_DELIM', data_len=self.data_len):
            self.do_bit_unstuffing = False

        if len(self.bits) < get_offset(packet_offsets, 'END', data_len=self.data_len):
            return False
        if len(self.bits) == get_offset(packet_offsets, 'END', data_len=self.data_len):
            mapped = map_bits_to_table(packet_offsets, self.bits, self.data_len)
            self.mapped = mapped
            calculated_crc = self.calculate_crc()
            if self.mapped['CRC'] != calculated_crc:
                self.error = 'CRC'
            # TODO find out a way to do anomaly detection in case it's neither of the two
            if self.voltage_difference <= THRESHOLD_VOLTAGE_DIFFERENCE:
                self.sender = 'PM'
            else:
                self.sender = 'JSM'
            return True
        assert False, "unreachable"

state = DemodFSM.IDLE
last_level = (selected_1[0] > THRESHOLD_VOLTAGE) # make sure we don't trigger an
last_edge = None # can be a real or virtual edge
decoder = None

low_time = 0

sample_times = []

idx = 0
jump_size = int(SAMPLES_PER_CAN_BIT  * 0.8)

limit = len(selected_1) - jump_size*2

while idx < limit:
    # TODO make this a shmitt-trigger instead
    # fast forward
    if state == DemodFSM.IDLE and not (selected_1[idx] > THRESHOLD_VOLTAGE):
        while idx < limit:
            new_idx = idx + jump_size
            if (selected_1[new_idx] > THRESHOLD_VOLTAGE):
                last_level = False
                break
            idx = new_idx
            low_time += jump_size

    level = selected_1[idx] > THRESHOLD_VOLTAGE
    edge = level != last_level
    last_level = level

    if state == DemodFSM.IDLE:
        if edge and low_time > 5*SAMPLES_PER_CAN_BIT:
            # positive edge seen
            assert level
            decoder = Packet(idx / SAMPLE_RATE)
            state = DemodFSM.SAMPLE
            last_edge = idx
    elif state == DemodFSM.SAMPLE:
        if idx == last_edge + SAMPLES_PER_CAN_BIT // 2:
            # TODO average this out over the entire bit duration (maybe +- 10%)
            average_1 = np.average(selected_1[int(idx - SAMPLES_PER_CAN_BIT *.4):int(idx + SAMPLES_PER_CAN_BIT *.4)])
            average_2 = np.average(selected_2[int(idx - SAMPLES_PER_CAN_BIT *.4):int(idx + SAMPLES_PER_CAN_BIT *.4)])
            should_stop = decoder.add_bit(level, average_1, average_2, idx)
            sample_times.append(idx)
            if should_stop:
                state = DemodFSM.FINISH
                if decoder.error is not None:
                    print(f"Error at idx {idx}")
            else:
                state = DemodFSM.EDGE_FIND
        else:
            idx = last_edge + SAMPLES_PER_CAN_BIT // 2 - 1
    elif state == DemodFSM.EDGE_FIND:
        if last_edge + int(SAMPLES_PER_CAN_BIT * 0.9) <= idx <= last_edge + int(SAMPLES_PER_CAN_BIT * 1.1):
            if edge:
                last_edge = idx
                state = DemodFSM.SAMPLE
        elif idx > last_edge + int(SAMPLES_PER_CAN_BIT * 1.1):
            last_edge = last_edge + SAMPLES_PER_CAN_BIT
            state = DemodFSM.SAMPLE
        elif idx < last_edge + int(SAMPLES_PER_CAN_BIT * 0.9) - 1:
            idx = last_edge + int(SAMPLES_PER_CAN_BIT * 0.9) - 1
    elif state == DemodFSM.FINISH:
        # TODO actually 3 bits recessive
        if idx > last_edge + int(SAMPLES_PER_CAN_BIT * 2):
            state = DemodFSM.IDLE
            packets.append(decoder)
    if not level:
        low_time += 1
    else:
        low_time = 0
    idx += 1

print(f'{len(packets)} packets found')

class Converter:
    def __init__(self, start_time: datetime.datetime, outfile_name: str, metadata: str):
        self.start_time = start_time
        self.outfile_name = outfile_name
        self.metadata = metadata

    def write(self, packets: list[Packet]):
        raise NotImplementedError()

class PcapNgConverter(Converter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def write(self, packets: list[Packet]):
        shb = blocks.SectionHeader(
            options={
                "shb_hardware": "CAN oscilloscope scope probes",
                "opt_comment": self.metadata
            }
        )
        idb = shb.new_member(
            blocks.InterfaceDescription,
            link_type=227, # linktype SocketCAN
            options={
                "if_name": "jsm0",
                "if_description": "joystick module",
            },
        )
        idb = shb.new_member(
            blocks.InterfaceDescription,
            link_type=227, # linktype SocketCAN
            options={
                "if_name": "pm0",
                "if_description": "power module",
            },
        )
        idb = shb.new_member(
                    blocks.InterfaceDescription,
                    link_type=227, # linktype SocketCAN
                    options={
                        "if_name": "unk0",
                        "if_description": "unknown",
                    },
                )
        with open(self.outfile_name, 'wb') as outfile:
            writer = FileWriter(outfile, shb)
            for packet in packets:
                spb = shb.new_member(blocks.EnhancedPacket)
                packetbytes = packet.as_scapy().__bytes__()
                spb.packet_data = bytes(packetbytes)
                time_us = int(packet.start_time * (1_000_000)) # seconds to us
                spb.timestamp_high = time_us >> 32
                spb.timestamp_low = time_us & 0xFFFFFFFF
                spb.interface_id = {'JSM': 0, 'PM': 1, None: 2}[packet.sender]
                writer.write_block(spb)

class CandumpConverter(Converter):
    def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

    def write(self, packets: list[Packet]):
        with open(self.outfile_name, 'w') as outfile:
            for packet in packets:
                if not packet.error:
                    address = f'{packet.can_id():08X}' if packet.is_extended_frame else f'{packet.can_id():03X}'
                    data = ''.join(f'{b:02X}' for b in packet.data())
                    interface = {'JSM': 'jsm0', 'PM': 'pm0', None: 'unk0'}[packet.sender]
                    print(f'({packet.start_time:.6f}) {interface} {address}#{data}{"R" if packet.rtr else ""}', file=outfile)

if args.pcapng is not None:
    PcapNgConverter(None, args.pcapng, METADATA).write(packets)
if args.candump is not None:
    CandumpConverter(None, args.candump, METADATA).write(packets)