# fw_0x420e.py
#
# Generic firmware file in case we do not know something...
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


class CYW20820A1(FirmwareDefinition):
    """
    CYW20820 is a Cypress evaluation board, the newest one that is currently available.

    Known issues:

    * `Launch_RAM` does not terminate and crashes the board.

      To get this working anyway:
      The `Launch_RAM` handler HCI callback is at `0xF2884` and it can be overwritten with the
      address of the memory snippet you want to launch. For example, at `0x219000` there is some
      free memory. Put the function there. Then:

      `internalblue.patchRom(0xF2884, p32(ASM_LOCATION_RNG+1)):  # function table entries are sub+1

    """

    # Firmware Infos
    # Evaluation Kit CYW920820
    FW_NAME = "CYW20820A1"


    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x001FFFFF, True, False),  # Internal ROM
        MemorySection(0x00200000, 0x0024FFFF, False, True),  # Internal Memory Cortex M3
        MemorySection(
            0x00270000, 0x0027FFFF, False, True
        ),  # Internal Memory Patchram Contents
        MemorySection(0x00310000, 0x00321FFF, False, True),  # HW Regs Cortex M3 (readable)
    ]

    # Patchram
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310404
    PATCHRAM_VALUE_TABLE_ADDRESS = 0x270000
    PATCHRAM_NUMBER_OF_SLOTS = 256
    PATCHRAM_ALIGNED = False
    # only seems to work 4-byte aligned here ...

    # Launch_RAM is faulty so we need to overwrite it. This is the position of the handler.
    LAUNCH_RAM = 0xF2884
    HCI_EVENT_COMPLETE = 0x1179E

    # Enable enhanced advertisement reports (bEnhancedAdvReport)
    ENHANCED_ADV_REPORT_ADDRESS = Address(0x20294C)


