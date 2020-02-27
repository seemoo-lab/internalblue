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
from .fw import MemorySection, FirmwareDefinition

class DefaultFirmware(FirmwareDefinition):
    # Firmware Infos
    FW_NAME = "default (unknown firmware)"

    # Memory Sections
    #                          start,    end,      is_rom? is_ram?
    SECTIONS = [ MemorySection(0x0,      0x90000,  True , False),
                 MemorySection(0xd0000,  0xd8000,  False, True ),
                 MemorySection(0x200000, 0x228000, False, True )
            ]
