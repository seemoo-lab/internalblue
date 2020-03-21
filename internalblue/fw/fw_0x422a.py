#!/usr/bin/env python

# MacBook 15" early 2011 tested with Ubuntu
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

from .fw import MemorySection, FirmwareDefinition


class BCM2070B0(FirmwareDefinition):
    # Firmware Infos
    FW_NAME = "BCM2070B0 (MacBook Pro 2011)"
    # Build date: Jul 9 2008

    # Memory Sections
    #                          start,    end,      is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x0, 0x58000, True, False),
        MemorySection(0x80000, 0x9B000, False, True),
    ]

    BLOC_HEAD = 0x88518
