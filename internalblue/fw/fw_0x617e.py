# fw_0x617e.py
#
# Generic firmware file in case we do not know something...
#
# Copyright (c) 2019 Jiska Classen. (MIT License)
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


class BCM4345B0(FirmwareDefinition):
    # Firmware Infos
    # iPhone 6
    FW_NAME = "BCM4345B0"


    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x000C07FF, True, False),  # Internal ROM
        MemorySection(
            0x000D0000, 0x000DFFFF, False, True
        ),  # Internal Memory Patchram Contents
        MemorySection(0x00200400, 0x00201CFF, False, True),  # Internal Memory Cortex M3
    ]

    # Patchram
    # PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000 #TODO needs to be aligned read
    # PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
    # PATCHRAM_VALUE_TABLE_ADDRESS    = 0xd0000
    # PATCHRAM_NUMBER_OF_SLOTS        = 128
    # PATCHRAM_ALIGNED                = True
    # only seems to work 4-byte aligned here ...
