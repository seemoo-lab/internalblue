#!/usr/bin/env python2

# fw_default.py
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
from .fw import MemorySection

# Firmware Infos
FW_NAME = "BCM20703A2 (MacBook Pro 2016)"

# Symbols contained in:
#   ./WICED-Studio-6.2/20706-A2_Bluetooth/Wiced-BT/BLD_ROM/A_20703A2/20703.symdefs
#   ./WICED-Studio-6.2/20706-A2_Bluetooth/Wiced-BT/tier2/brcm/wiced_uart/bld/A_20703A2/20703_ram_ext.lst

# Memory Sections
#                          start,    end,      is_rom? is_ram?
SECTIONS = [
    MemorySection(0x0, 0xC7FFF, True, False),  # 0x000c0a97
    MemorySection(0xD0000, 0xE0000, False, False),  # 0x000dd78c
    MemorySection(0x200000, 0x240000, False, True),  # 0x00217a38
    MemorySection(0x260000, 0x268FFF, True, False),  # 0x0026841d
    MemorySection(0x318000, 0x320000, False, False),
    MemorySection(0x324000, 0x338000, False, False),
    MemorySection(0x362000, 0x362100, False, False),
    MemorySection(0x363000, 0x363100, False, False),
    MemorySection(0x600000, 0x600800, False, False),
    MemorySection(0x640000, 0x640800, False, False),
    MemorySection(0x650000, 0x650800, False, False),
]
