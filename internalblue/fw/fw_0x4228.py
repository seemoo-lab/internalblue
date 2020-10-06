# fw_0x4228.py
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


class BCM4378B1(FirmwareDefinition):
    # Firmware Infos
    # iPhone 11/SE2
    FW_NAME = "BCM4378B1"

    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    # TODO hardware registers not contained in here yet
    SECTIONS = [
        MemorySection(0x00000000, 0x0013FFFF, True, False),  # Internal ROM
        MemorySection(
            0x00170000, 0x0018FFFF, False, True
        ),  # Internal Memory Patchram Contents
        MemorySection(0x00200000, 0x0024FFFF, False, True),  # Internal Memory Cortex M3
        MemorySection(
            0x00270000, 0x002AFFFF, False, True
        ),  # Internal Memory Patchram Contents, Part 2
    ]


    # Patchram, relocated since a loooong time :D
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x360000
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x360404
    PATCHRAM_VALUE_TABLE_ADDRESS = 0x170000
    PATCHRAM_NUMBER_OF_SLOTS = 256  # all slots except the last one used on the iPhone 11 on iOS 13.5 /o\
    PATCHRAM_ALIGNED = False
