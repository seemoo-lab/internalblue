#!/usr/bin/env python

# fw_0x6119.py
#
# All firmware specific data such as address offsets are collected
# in the fw.py file. Later versions of the framework will provide
# multiple copies of this file in order to target different firmware
# and chip versions.
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

# Firmware Infos
# This runs on Rasperry Pi 3+


from __future__ import absolute_import
from .fw import MemorySection, FirmwareDefinition
from .. import Address


class BCM4345C0(FirmwareDefinition):
    FW_NAME = "BCM4345C0"

    # Device Infos
    DEVICE_NAME = 0x204954

    # Memory Sections
    #                          start,    end,      is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x0, 0x90000, True, False),
        MemorySection(0xD0000, 0xD8000, False, True),
        # MemorySection(0xe0000,  0x1f0000, True , False),
        MemorySection(0x200000, 0x228000, False, True),
        MemorySection(0x260000, 0x268000, True, False),
        # MemorySection(0x280000, 0x2a0000, True , False),
        MemorySection(0x318000, 0x320000, False, False),
        MemorySection(0x324000, 0x360000, False, False),
        MemorySection(0x362000, 0x362100, False, False),
        MemorySection(0x363000, 0x363100, False, False),
        MemorySection(0x600000, 0x600800, False, False),
        MemorySection(0x640000, 0x640800, False, False),
        MemorySection(0x650000, 0x650800, False, False),
        # MemorySection(0x680000, 0x800000, False, False)
    ]

    # Connection Structure and Table
    CONNECTION_ARRAY_ADDRESS = 0x204BA8
    CONNECTION_MAX = 11
    CONNECTION_STRUCT_LENGTH = 0x150

    # Patchram
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000
    PATCHRAM_VALUE_TABLE_ADDRESS = 0xD0000
    PATCHRAM_NUMBER_OF_SLOTS = 128
    PATCHRAM_ALIGNED = False

    # Heap
    BLOC_HEAD = 0x200490  # g_dynamic_memory_GeneralUsePools
    BLOC_NG = True  # Next Generation Bloc Buffer

    # Enable enhanced advertisement reports (bEnhancedAdvReport) - TODO untested
    ENHANCED_ADV_REPORT_ADDRESS = Address(0x202CC4)

    # Snippet for sendLcpPacket()
    SENDLCP_CODE_BASE_ADDRESS = 0x21F000
    SENDLCP_ASM_CODE = """
            push {r4,lr}
    
            // we want to call lmulp_sendLcp(conn_index, input, length)
    
            mov r0,  %d     // connection index, starts at 0
            ldr r1, =payload
            mov r2, %d      // length
            bl  0x92062     // lmulp_sendLcp
    
            pop {r4,pc}     // go back
    
            .align          // The payload (LMP packet) must be 4-byte aligend (memcpy needs aligned addresses)
            payload:        // Note: the payload will be appended here by the sendLmpPacket() function
            """
