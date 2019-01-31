#!/usr/bin/env python2

# fw.py
#
# Implements all types of Broadcom Bluetooth firmware we know or loads default
# firmware instead.
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

from pwn import *

class Firmware:
    def __init__(self, version=None, vendor=None):
        """
        Load and initialize the actual firmware add-ons for Nexus 5, Raspi3, etc.

        :param version: LMP subversion that identifies the firmware.
        :param vendor:  Vendor ID, 0xf is Broadcom and 0x131 is Cypress
        """

        self.version = version
        self.firmware = None

        if version:
            # get LMP Subversion
            log.info("Chip identifier: 0x%04x (%03d.%03d.%03d)" % (version, version>>13, (version&0xf00)>>8, version&0xff))
            try:
                self.firmware = __import__('fw.fw_' + hex(version), fromlist=[''])
            except:
                self.firmware = None
                pass

        if not version or not self.firmware:
            self.firmware = __import__('fw.fw_default', fromlist=[''])

        log.info("Loaded firmware information for " + self.firmware.FW_NAME + ".")

        #return self.firmware


class MemorySection:
    """
    All firmwares have memory sections that can be RAM, ROM or neither of both.
    """
    def __init__(self, start_addr, end_addr, is_rom, is_ram):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.is_rom = is_rom
        self.is_ram = is_ram

    def size(self):
        return self.end_addr - self.start_addr
