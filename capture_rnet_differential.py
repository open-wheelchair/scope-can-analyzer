#!/usr/bin/python3

# SPDX-License-Identifier: GPL-3.0-only
# Based on code from github.com/Ho-Ro/Hantek6022API/PyHT6022/LibUsbScope.py

DESCRIPTION = """Capture CAN traffic to a compressed numpy file.
With only 1 probe, you can normally only identify the traffic, but not which node on the bus sent it.
This program uses two probes to also identify which side the packets originated from.

Connection guide:

- Cut the white wire (CAN high) in between the joystick and power module
- Insert a 10 ohm resistor in between
- Set both oscilloscope probes to 10x
- Connect channel 1 (yellow) to the resistor on the side of the joystick
- Connect channel 2 (blue) to the resistor on the side of the power module
"""

from PyHT6022.LibUsbScope import Oscilloscope
import numpy as np

import sys
import time
import os
import sys
import argparse


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=DESCRIPTION
)

parser.add_argument(
    "--outfile",
    help="Path to the output file (recommend ends with .npz)",
    required=True
)

parser.add_argument(
    "--duration",
    type=float,
    help="Capture duration in seconds",
    required=True
)

parser.add_argument(
    "--capture-info",
    help="Capture information (suggestion: describe starting state and what actions will be taken)",
    nargs="?",
    default=""
)

parser.add_argument(
    "--ask-extra-comment-post-capture",
    action="store_true",
    default=False,
    help="Interactively ask for extra comment string post capture",
)
args = parser.parse_args()

METADATA = args.capture_info
OUTFILE = args.outfile

if os.path.exists(OUTFILE):
    print(f'{OUTFILE} already exists')
    sys.exit(1)

time_to_sample_s = args.duration

sample_rate_index = 10 # 10 MS/s
sample_rate = 10_000_000

# Range with attenuator: -5 to 5V
voltage_range = 0x0a
probe_attenuation = 10

data_points_per_callback = 3 * 1024

scope = Oscilloscope()
scope.setup()
if not scope.open_handle():
    print("Scope not found")
    sys.exit()
scope.flash_firmware()
scope.set_interface(1) # choose ISO
scope.set_num_channels(2)
scope.set_sample_rate(sample_rate_index)
scope.set_ch1_voltage_range(voltage_range)
scope.set_ch2_voltage_range(voltage_range)
scope.get_calibration_values()
time.sleep(1)


num_samples = time_to_sample_s * sample_rate_index * 1000 * 1000

data = np.zeros((2, num_samples), dtype=np.uint8)

current_sample_idx = 0
pre_run_skip = 100_000

def extend_callback(ch1_data, ch2_data):
    # static variable
    global current_sample_idx, pre_run_skip
    if pre_run_skip > 0:
        pre_run_skip -= len(ch1_data)
        return

    assert len(ch1_data) == len(ch2_data)
    size = min(num_samples - current_sample_idx, len(ch1_data))
    if size == 0:
        return
    data[0][current_sample_idx:current_sample_idx+size] = np.frombuffer(ch1_data, dtype=np.uint8)[:size]
    data[1][current_sample_idx:current_sample_idx+size] = np.frombuffer(ch2_data, dtype=np.uint8)[:size]
    current_sample_idx += size

start_time = time.time()
print("START CAPTURE NOW")
i = 0
scope.start_capture()
shutdown_event = scope.read_async(extend_callback, data_points_per_callback, outstanding_transfers=50, raw=True)

countup = 0

while time.time() - start_time < time_to_sample_s + 0.5:
    scope.poll()
    if time.time() - start_time > countup:
        print(time_to_sample_s - countup)
        countup += 1

scope.stop_capture()
print("Stopping new transfers.")
shutdown_event.set()
print("Snooze 1")
time.sleep(1)
print("Closing handle")
scope.close_handle()
print("Handle closed.")
print("Points in buffer:", current_sample_idx, "expected", num_samples)

def scale_read_data_np(scope, read_data, voltage_range=1, channel=1, probe=1, offset=0):
    """
    Convenience function for converting data read from the scope to nicely scaled voltages.
    Apply the calibration values that are stored in EEPROM (call "get_calibration_values()" before)
    :param list read_data: The list of points returned from the read_data functions.
    :param int voltage_range: The voltage range current set for the channel.
    :param int channel: 1 = CH1, 2 = CH2.
    :param int probe_multiplier: (OPTIONAL) An additonal multiplictive factor for changing the probe gain.
                                Default: 1
    :param int offset: (OPTIONAL) An additional additive value to compensate the ADC offset
    :return: A list of correctly scaled voltages for the data.
    """
    if channel == 1:
            mul = probe * scope.gain1[ voltage_range ]
            off = offset + scope.offset1[ voltage_range ]
    else:
            mul = probe * scope.gain2[ voltage_range ]
            off = offset + scope.offset2[ voltage_range ]

    scale_factor = ( 5.12 * mul ) / ( voltage_range << 7 )
    data = (np.array(read_data, dtype=float) - 128 - off) * scale_factor
    return data

print("Rescaling...")
scaled_ch_1 = scale_read_data_np(scope, data[0], voltage_range, probe=probe_attenuation, channel=1)
scaled_ch_2 = scale_read_data_np(scope, data[1], voltage_range, probe=probe_attenuation, channel=2)

print("Saving...")

if args.ask_extra_comment_post_capture:
    extra_comment = input("Extra comment? (Enter to continue) > ")
else:
    extra_comment = ''

capture_info = f'CAN traffic capture; channel 1 = can high joystick side; channel 2 = can high power module side; 10 ohm resistor in between; {sample_rate} samples/s'

np.savez_compressed(OUTFILE, scaled_ch_1=scaled_ch_1, scaled_ch_2=scaled_ch_2, metadata=METADATA, extra_comment=extra_comment, capture_info=capture_info, sample_rate=sample_rate)
