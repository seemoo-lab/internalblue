#!/usr/bin/env python

# fw_0x2056.py
#
# Copyright (c) 2020 The InternalBlue Team. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.

from __future__ import absolute_import
from .fw import MemorySection, FirmwareDefinition
from .. import Address


class BCM4364B0(FirmwareDefinition):
    # Firmware Infos
    # Various MacBooks/iMacs ranging from 2016 to 2019.
    # Note that with each OS update the LMP version changes on macOS, so you might
    # need to rename the file to the LMP minor version you see in your macOS hardware
    # report. It was 0x2056 in April 2020.
    FW_NAME = "BCM4364B0"

    # Memory Sections - untested!
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x0013FFFF, True, False),  # Internal ROM
        MemorySection(0x00160000, 0x0017FFFF, False, True),  # Patches
        MemorySection(0x00200000, 0x00288000, False, True),  # Internal Memory Cortex M3
        MemorySection(0x00300000, 0x0037FFFF, False, True),
    ]

    # Patchram - untested!
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310404
    PATCHRAM_VALUE_TABLE_ADDRESS = 0x160000
    PATCHRAM_NUMBER_OF_SLOTS = 256
    PATCHRAM_ALIGNED = False

    # Enable enhanced advertisement reports (bEnhancedAdvReport)
    ENHANCED_ADV_REPORT_ADDRESS = Address(0x203154)

