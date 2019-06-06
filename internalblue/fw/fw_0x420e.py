# fw_0x420e.py
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

from fw import MemorySection

# Firmware Infos
# Evaluation Kit CYW927019
FW_NAME = "CYW27039B1"

# Device Infos
DEVICE_NAME = 0x280CD0                  # rm_deviceLocalName, FIXME has no longer a length byte prepended
BD_ADDR = 0x280CA4                      # rm_deviceBDAddr

#Heap
BLOC_HEAD = 0x0200c7c                   # g_dynamic_memory_GeneralUsePools
BLOC_NG = True                          # Next Generation Bloc Buffer

# Memory Sections
#                          start,    end,           is_rom? is_ram?
SECTIONS = [ MemorySection(0x00000000, 0x001fffff,  True,  False),  # Internal ROM
             MemorySection(0x00200000, 0x0024ffff,  False, True),   # Internal Memory Cortex M3
             MemorySection(0x00270000, 0x0027ffff,  False, True),   # Internal Memory Patchram Contents
             MemorySection(0x00280000, 0x00283fff,  False, True),   # ToRam
            ]

# Patchram
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310404
PATCHRAM_VALUE_TABLE_ADDRESS    = 0x270000
PATCHRAM_NUMBER_OF_SLOTS        = 192
PATCHRAM_ALIGNED                = False
# only seems to work 4-byte aligned here ...


