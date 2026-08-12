#!/usr/bin/env python

# fw_0x6209.py
#
# Firmware definition for the Broadcom BCM4389C1 (LMP subversion 0x6209),
# the internal Bluetooth controller of the Google Pixel 6 ("oriole") and
# related GS101/GS201 devices.
#
# All firmware-specific data such as address offsets are collected here, in
# the same style as the other fw_0x****.py modules. Values are taken from
# on-device reverse engineering (see the class docstring); anything not yet
# confirmed is left as an explicit TODO rather than guessed.
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


class BCM4389C1(FirmwareDefinition):
    """
    BCM4389C1 is the internal Bluetooth controller in the Google Pixel 6
    ("oriole"). It is a Cortex-M4 (r0p1, CPUID 0x410FC241) FullMAC-class BT
    controller, HCI/LMP 5.2, reported by HCI Read_Local_Version_Information as:

        HCI 5.2 (0xb)  Revision 0x20cb  LMP 5.2 (0xb)  Subversion 0x6209
        Manufacturer: Broadcom Corporation (15)
        Name: 'BCM4389C1 ES1PX_GG_06 ...'

    The 0x6209 subversion selects this module.

    Notes / caveats for this controller:

    * On the running (patched) firmware the vendor memory commands
      READ_RAM (0xFC4D), WRITE_RAM (0xFC4C) and LAUNCH_RAM (0xFC4E) are
      LOCKED and return status 0x0C (Command Disallowed). Standard HCICore
      readMem/writeMem/launchRam therefore do NOT work out of the box on this
      chip; a diagnostic-channel (H4 type 0x07) backend is required for
      memory access. This module supplies the correct identity and memory
      map; the diag-backed read/write transport is a separate follow-up.

    * The SECTIONS bounds below are measured on-device (bootloader READ_RAM
      extent probe). The patchram control-table / launch-handler addresses
      are not yet resolved from ROM RE and are left as TODO.
    """

    # Firmware Infos
    # Google Pixel 6 ("oriole") internal Bluetooth controller.
    FW_NAME = "BCM4389C1"

    # Device Infos
    # DEVICE_NAME / BD_ADDR are the RAM addresses at which the controller
    # caches its local name / BD_ADDR. The BD_ADDR cache was located
    # empirically on one device (a runtime location that can move with a fw
    # rebuild or a different SKU), so it is intentionally NOT hardcoded here;
    # a stable, ROM-symbol-derived address is needed before relying on it.
    # DEVICE_NAME = 0x????????  # TODO (locate the local-name struct in RAM)
    # BD_ADDR     = 0x????????  # TODO (BD_ADDR RAM cache; do not hardcode the
    #                           #       per-device empirical offset)

    # Memory Sections
    # ROM extent and RAM extent are MEASURED on-device via the bootloader
    # READ_RAM probe (a clean out-of-range status byte marks each boundary):
    #   ROM : data returned 0x0..0x1DFFB0, then out-of-range above the top
    #         (architectural ROM boundary is < 0x001E0000).
    #   RAM : 819,250 B read from 0x200000, out-of-range at 0x2C8032
    #         (real top ~= 0x002C8000). Contiguous & fully mapped. The
    #         vector-table SP (word[0]) is 0x00200400.
    # The R2-R5 RAM code segments (~0x210000-0x260000) and the software
    # patch/slot tables (~0x2C2000-0x2C8000) both fall inside this single
    # contiguous RAM section. The peripheral/register window at 0x40000000+
    # is NOT mapped as a section (bounds unconfirmed; do not blind-read it).
    #                          start,      end,        is_rom, is_ram
    SECTIONS = [
        MemorySection(0x00000000, 0x001DFFB0, True,  False),  # Internal ROM (~1.875 MB)
        MemorySection(0x00200000, 0x002C8000, False, True),   # Internal RAM (~800 KB)
    ]

    # Patchram
    # The BCM4389C1 uses a hardware fetch-redirect patchram covering a bounded
    # ROM range. However, the hardware patchram CONTROL registers that
    # InternalBlue's patchRom() needs -- the target table, the enabled bitmap
    # and the value table -- have not yet been resolved from ROM RE. They are
    # left as TODO rather than copied from an older Broadcom part, because
    # guessing them (e.g. the classic 0x310000 register base) would be wrong here.
    # PATCHRAM_TARGET_TABLE_ADDRESS   = 0x????????  # TODO
    # PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x????????  # TODO
    # PATCHRAM_VALUE_TABLE_ADDRESS    = 0x????????  # TODO
    # PATCHRAM_NUMBER_OF_SLOTS        = ????         # TODO
    # PATCHRAM_ALIGNED                = True         # TODO (verify alignment)

    # Launch RAM / HCI complete handler
    # LAUNCH_RAM is locked on the running fw (0x0C); the handler address is not
    # yet resolved. Left as TODO.
    # LAUNCH_RAM         = 0x????????  # TODO
    # HCI_EVENT_COMPLETE = 0x????????  # TODO
