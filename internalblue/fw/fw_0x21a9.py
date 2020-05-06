# fw_default.py
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


class BCM20703A1(FirmwareDefinition):
    # Firmware Infos
    # MacBook Pro early 2015 15" Retina
    # macOS changes the LMP version with security fixes
    # 10.15.4 has 0x21a9 but older patches go down to 0x21a1
    FW_NAME = "BCM20703A1"

    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x000C7FFF, True, False),  # Internal ROM
        MemorySection(0x000D0000, 0x000EFFFF, False, True),  # Patchram
        MemorySection(0x00200000, 0x00247FFF, False, True),  # Internal Memory Cortex M3
    ]

    # Patchram
    # needs aligned access on this firmware, so it doesn't work
