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
# Samsung S10/S10e/S10+
FW_NAME = "BCM4375B1"


# Device Infos
DEVICE_NAME = 0x207f2a
BD_ADDR = 0x2026e2


# Memory Sections
#                          start,    end,           is_rom? is_ram?
SECTIONS = [ MemorySection(0x00000000, 0x0013ffff,  True,  False),  # Internal ROM
             MemorySection(0x00160000, 0x0017ffff,  False, True),   # Patches
             MemorySection(0x00200000, 0x0023ffff,  False, True),   # Internal Memory Cortex M3
             MemorySection(0x00240000, 0x0027ffff,  True,  False),
             MemorySection(0x00300000, 0x0037ffff,  False, True),
             ]

# Patchram
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310404
PATCHRAM_VALUE_TABLE_ADDRESS    = 0x160000
PATCHRAM_NUMBER_OF_SLOTS        = 256
PATCHRAM_ALIGNED                = False


