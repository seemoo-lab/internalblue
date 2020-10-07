#!/usr/bin/env python

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

from builtins import hex
from builtins import object
from types import ModuleType
from typing import List


from internalblue import Address
import logging

from internalblue.utils.logging_formatter import CustomFormatter


class MemorySection(object):
    """
    All firmwares have memory sections that can be RAM, ROM or neither of both.
    """

    def __init__(self, start_addr, end_addr, is_rom, is_ram):
        self.start_addr: Address = start_addr
        self.end_addr: Address = end_addr
        self.is_rom: bool = is_rom
        self.is_ram: bool = is_ram

    def size(self) -> int:
        return self.end_addr - self.start_addr


class FirmwareDefinition:

    DEVICE_NAME: Address

    BD_ADDR: Address

    SECTIONS: List[MemorySection]
    TRACEPOINT_BODY_ASM_SNIPPET: str
    TRACEPOINT_HOOKS_LOCATION: int
    TRACEPOINT_RAM_DUMP_PKT_COUNT = None

    CONNECTION_STRUCT_LENGTH: int

    FW_NAME: str

    QUEUE_NAMES: List[str]
    QUEUE_HEAD: Address
    BLOC_HEAD: Address
    SENDLCP_CODE_BASE_ADDRESS: Address

    SENDLCP_ASM_CODE: str

    SENDLMP_CODE_BASE_ADDRESS: Address
    SENDLMP_ASM_CODE: str

    FUZZLMP_HOOK_ADDRESS: Address
    FUZZLMP_CODE_BASE_ADDRESS: Address
    FUZZLMP_ASM_CODE: str

    CONNECTION_LIST_ADDRESS: Address
    CONNECTION_ARRAY_ADDRESS: Address
    CONNECTION_MAX: int

    PATCHRAM_VALUE_TABLE_ADDRESS: Address
    PATCHRAM_TARGET_TABLE_ADDRESS: Address
    PATCHRAM_ENABLED_BITMAP_ADDRESS: Address
    PATCHRAM_ALIGNED: bool
    PATCHRAM_NUMBER_OF_SLOTS: int

    LAUNCH_RAM_PAUSE = None
    LAUNCH_RAM = Address
    HCI_EVENT_COMPLETE = Address

    READ_MEM_ALIGNED_ASM_LOCATION: Address
    READ_MEM_ALIGNED_ASM_SNIPPET: str

    TRACEPOINT_HOOK_SIZE = None
    TRACEPOINT_BODY_ASM_LOCATION: Address
    TRACEPOINT_HOOK_ASM = None

    ENHANCED_ADV_REPORT_ADDRESS: Address


class Firmware(object):
    firmware: FirmwareDefinition

    def __init__(self, version=None, iOS=False):
        """
        Load and initialize the actual firmware add-ons for Nexus 5, Raspi3, etc.

        :param version: LMP subversion that identifies the firmware.
        """

        self.version = version

        logger = logging.getLogger("InternalBlue")
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(CustomFormatter())
        if not logger.hasHandlers():
            logger.addHandler(ch)

        if version:
            # get LMP Subversion
            logger.info(
                "Chip identifier: 0x%04x (%03d.%03d.%03d)"
                % (version, version >> 13, (version & 0xF00) >> 8, version & 0xFF)
            )

            try:
                # Fix for duplicate version number of evaluation board / iPhones
                if iOS and version == 0x420E:
                    self.firmware = self._module_to_firmware_definition(
                        __import__(
                            __name__ + "_" + hex(version) + "_iphone", fromlist=[""]
                        )
                    )
                    logger.info("Using fw_" + hex(version) + "_iphone.py")
                else:
                    self.firmware = self._module_to_firmware_definition(
                        __import__(__name__ + "_" + hex(version), fromlist=[""])
                    )
                    logger.info("Using fw_" + hex(version) + ".py")
            except ImportError:
                self.firmware = None
                pass

        if not version or not self.firmware:
            self.firmware = self._module_to_firmware_definition(
                __import__(__name__ + "_default", fromlist=[""])
            )

        logger.info("Loaded firmware information for " + self.firmware.FW_NAME + ".")

    def _module_to_firmware_definition(self, fw: ModuleType) -> FirmwareDefinition:
        """
        Wrap existing usages where the module was used and extract the new FirmwareDefinition class

        :param fw:
        :return:
        """
        _types = {
            name: cls
            for name, cls in fw.__dict__.items()
            if isinstance(cls, type)
            and issubclass(cls, FirmwareDefinition)
            and not cls is FirmwareDefinition
        }

        if len(_types) == 1:
            return list(_types.values())[0]
