#!/usr/bin/env python

# fw_0x6103.py
#
# Copyright (c) 2019 Dennis Heinze. (MIT License)
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


class BCM4355C0(FirmwareDefinition):
    # Firmware Infos
    # This runs on an iPhone 7
    FW_NAME = "BCM4355C0"

    # Device Infos
    DEVICE_NAME = 0x204C60

    # Memory Sections
    #                          start,    end,      is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x0, 0x90000, True, False),
        MemorySection(0xD0000, 0xD8000, False, True),
        MemorySection(0x200000, 0x228000, False, True),
        MemorySection(0x318000, 0x320000, False, False),
        MemorySection(0x324000, 0x360000, False, False),
        MemorySection(0x362000, 0x362100, False, False),
        MemorySection(0x363000, 0x363100, False, False),
        #MemorySection(0x600000, 0x600800, False, False),
        #MemorySection(0x640000, 0x640800, False, False),
    ]

    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
    PATCHRAM_VALUE_TABLE_ADDRESS = 0xD0000
    PATCHRAM_NUMBER_OF_SLOTS = 192
    PATCHRAM_ALIGNED = False
