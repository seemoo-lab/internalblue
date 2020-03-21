#!/usr/bin/env python
#
# fw_0x220e.py
#
# Firmware file for BCM20702A1 chipsets. These chipsets are typically used for
# Bluetooth USB dongles.
#
# Copyright (c) 2019 Jan Ruge and Jiska Classen. (MIT License)
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
from __future__ import absolute_import


class BCM20702A1(FirmwareDefinition):
    # Firmware Infos
    FW_NAME = "BCM20702A1"  # (USB Bluetooth dongle)

    # Device Infos
    # DEVICE_NAME = 0x280CD0                  # rm_deviceLocalName, FIXME has no longer a length byte prepended
    # BD_ADDR = 0x280CA4                      # rm_deviceBDAddr

    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x5FFFF, True, False),  # Internal ROM
        MemorySection(0x80000, 0x9BFFF, False, True),  # Internal RAM
    ]
    BLOC_HEAD = 0x3166C
