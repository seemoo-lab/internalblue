#!/usr/bin/env python2

# cli.py
#
# This file is meant to be executed by the user in order to start
# an interactive CLI. It creates an instance of the framework and
# enters a command loop which is implemented using cmd2.
# Commands entered by the user are automatically matched
# to functions starting with do_* and executed accordingly.
#
# Copyright (c) 2018 Dennis Mantz. (MIT License)
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


from __future__ import print_function

import argparse
import binascii
import inspect
import os
import re
import select
import struct
import subprocess
import sys
import time
from builtins import str
from curses.ascii import isprint
from threading import Timer
from functools import wraps

import cmd2
from cmd2 import fg, style

from . import Address
from .hci import HCI_COMND
from .utils import bytes_to_hex, flat, yesno
from .utils.packing import p8, p16, p32, u32
from .utils.progress_logger import ProgressLogger
from .utils.internalblue_logger import getInternalBlueLogger
from .hcicore import HCICore
from .adbcore import ADBCore

try:
    import typing
    from typing import List, Optional, Any, TYPE_CHECKING, Type, cast
    from internalblue.core import InternalBlue
    from . import DeviceTuple

    if TYPE_CHECKING:
        from internalblue.core import InternalBlue
        from internalblue import Record, BluetoothAddress, Address
except ImportError:
    pass

try:
    from pwnlib import context
    from pwnlib.asm import disasm, asm
    from pwnlib.exception import PwnlibException
    context.context.arch = 'thumb'
except ImportError:
    context = disasm = asm = PwnlibException = None
    _has_pwnlib = False
else:
    _has_pwnlib = True


def needs_pwnlib(func):
    # this decorator copies over
    # function name, docstring,
    # arguments list etc. so our
    # help command still works
    @wraps(func)
    def inner(*args, **kwargs):
        if not _has_pwnlib:
            raise ImportError("pwnlib is required for this function.")
        return func(*args, **kwargs)

    return inner


def auto_int(x):
    """ Convert a string (either decimal number or hex number) into an integer.
    """

    # remove leading zeros as this doesn't work with int(), issue 20
    # but only for integers (023), not for hex (0x23)
    if not ('x' in x):
        x = x.lstrip('0')
    return int(x, 0)


def read(path, count=-1, skip=0):
    r"""read(path, count=-1, skip=0) -> str

    Open file, return content.

    Examples:
        >>> read('/proc/self/exe')[:4]
        b'\x7fELF'
    """
    path = os.path.expanduser(os.path.expandvars(path))
    with open(path, 'rb') as fd:
        if skip:
            fd.seek(skip)
        return fd.read(count)


class InternalBlueCLI(cmd2.Cmd):
    def __init__(self, main_args, core: InternalBlue = None):
        # get and store 'InternalBlue' logger
        self.logger = getInternalBlueLogger()

        # create progress logger
        self.progress_log = None

        # set prompt
        self.prompt = '> '

        # Prints an intro banner once upon application startup
        banner = r"   ____     __                    _____  __ " + "\n" \
                 + r"  /  _/__  / /____ _______  ___ _/ / _ )/ /_ _____" + "\n" \
                 + r" _/ // _ \/ __/ -_) __/ _ \/ _ `/ / _  / / // / -_)" + "\n" \
                 + r"/___/_//_/\__/\__/_/ /_//_/\_,_/_/____/_/\_,_/\__/" + "\n" + "\n" \
                 + "type <help -v> for usage information!"

        self.intro = style(banner, fg=fg.blue)

        # History file
        if main_args.data_directory is not None:
            data_directory = main_args.data_directory
        else:
            data_directory = os.path.expanduser("~") + "/.internalblue"
        if not os.path.exists(data_directory):
            os.mkdir(data_directory)

        # Define shortcuts for commands (before call to super())
        shortcuts = dict(cmd2.DEFAULT_SHORTCUTS)
        shortcuts.update({
            'bye': 'exit',
            'verbosity': 'loglevel', 'log_level': 'loglevel',
            'wireshark': 'monitor',
            'watch': 'repeat',
            'memdump': 'dumpmem',
            'memsearch': 'searchmem',
            'hd': 'hexdump', 'readmem': 'hexdump',
            'disassemble': 'disasm',
            'asm': 'writeasm',
            'execute': 'exec',
            'show': 'info',
            'tp': 'tracepoint',
            'bp': 'breakpoint',
            'heap': 'memorypool', 'pool': 'memorypool',
            'leconnect': 'connectle', 'cle': 'connectle', 'lec': 'connectle',
            'sendh4': 'diag'})

        super().__init__(shortcuts=shortcuts, persistent_history_file=data_directory + "/_internalblue.hist", use_ipython=True)

        # Aliases have to be used instead of shortcuts
        # When the alias is equal with the beginning
        # of a command name. Has to be called after super().
        self.runcmds_plus_hooks(["alias create break breakpoint > /dev/null",
                                 "alias create trace tracepoint > /dev/null",
                                 "alias create tel telescope > /dev/null",
                                 "alias create disas disasm > /dev/null",
                                 "alias create d disasm > /dev/null",
                                 "alias create i info > /dev/null",
                                 "alias create q quit > /dev/null"],
                                add_to_history=False)

        # Settings
        if main_args.verbose:
            log_level = "debug"
        else:
            log_level = "info"

        HookClass = None
        if main_args.trace:
            from .socket_hooks import hook
            from internalblue import socket_hooks
            HookClass = getattr(socket_hooks, main_args.trace)
            hook(HCICore, HookClass)
            hook(ADBCore, HookClass)
        elif main_args.save:
            from .socket_hooks import hook, TraceToFileHook
            hook(HCICore, TraceToFileHook, filename=main_args.save)
            hook(ADBCore, TraceToFileHook, filename=main_args.save)

        # Connection method passed in constructor (POCs)
        if core is not None:
            self.internalblue = core
            return
        # Connection methods for replay script
        elif main_args.replay:
            connection_methods: List[InternalBlue] = self._get_connection_methods_replay(main_args, log_level, data_directory)
        # Connection methods for normal operation
        else:
            connection_methods: List[InternalBlue] = self._get_connection_methods_normal(main_args, log_level, data_directory, HookClass)

        devices = []  # type: List[DeviceTuple]
        for connection_method in connection_methods:
            devices.extend(connection_method.device_list())

        device = None  # type: Optional[DeviceTuple]
        if len(devices) > 0:
            if main_args.replay:
                # There should only be one device that was created when --replay was passed
                device = devices[0]
            elif main_args.device:
                matching_devices = [dev for dev in devices if dev[1] == main_args.device]
                if len(matching_devices) > 1:
                    self.logger.critical("Found multiple matching devices")
                    exit(-1)
                elif len(matching_devices) == 1:
                    self.logger.info("Found device is: {}".format(matching_devices[0]))
                    device = matching_devices[0]
                else:
                    self.logger.critical("No matching devices found")
                    exit(-1)
            elif len(devices) == 1:
                device = devices[0]
            else:
                i = self.options("Please specify device:", [d[2] for d in devices])
                device = devices[i]

            # Setup device
            self.internalblue = device[0]
            self.internalblue.interface = device[1]

            self.memory_image_template_filename = (
                    self.internalblue.data_directory + "/memdump__template.bin"
            )
            self.memory_image: Optional[bytes] = None

            # Connect to device
            if not self.internalblue.connect():
                self.logger.critical("No connection to target device.")
                exit(-1)

            # Enter command loop (runs until user quits)
            self.logger.info("Starting commandLoop for self.internalblue {}".format(self.internalblue))

    def _get_connection_methods_replay(self, main_args, log_level, data_directory) -> [InternalBlue]:
        from .socket_hooks import hook, ReplaySocket
        from .macoscore import macOSCore

        replay_devices = ["macos_replay", "adb_replay", "hci_replay", "ios_replay"]
        if main_args.device == "macos_replay":
            from .macoscore import macOSCore

            hook(macOSCore, ReplaySocket, filename=main_args.replay)
            connection_methods = [
                macOSCore(
                    log_level=log_level, data_directory=data_directory, replay=True
                )
            ]
        elif main_args.device == "hci_replay":
            hook(HCICore, ReplaySocket, filename=main_args.replay)
            connection_methods = [
                HCICore(log_level=log_level, data_directory=data_directory, replay=True)
            ]
        elif main_args.device == "adb_replay":
            hook(ADBCore, ReplaySocket, filename=main_args.replay)
            connection_methods = [
                ADBCore(log_level=log_level, data_directory=data_directory, replay=True)
            ]
        elif main_args.device == "ios_replay":
            raise NotImplementedError("ios replay is not implemented yet")
        else:
            raise ValueError(
                "--device is required with --replay and has to be one of {}".format(
                    replay_devices
                )
            )
        return connection_methods

    def _get_connection_methods_normal(self, main_args, log_level, data_directory, HookClass):
        from internalblue.socket_hooks import TraceToFileHook

        # if /var/run/usbmuxd exists, we can check for iOS devices
        connection_methods = []
        if os.path.exists("/var/run/usbmuxd"):
            from .ioscore import iOSCore
            connection_methods.append(iOSCore(log_level=log_level, data_directory=data_directory))
        if sys.platform == "darwin":
            try:
                from .macoscore import macOSCore
                connection_methods.append(macOSCore(log_level=log_level, data_directory=data_directory,
                                                    replay=(main_args.replay and main_args.device == "mac")))
            except ImportError:
                macOSCore = None
                self.logger.warning("Couldn't import macOSCore. Is IOBluetoothExtended.framework installed?")
            if main_args.trace:
                from .socket_hooks import hook
                hook(macOSCore, HookClass)
            elif main_args.save:
                from .socket_hooks import hook
                hook(macOSCore, TraceToFileHook, filename=main_args.save)
        else:
            connection_methods.append(HCICore(log_level=log_level, data_directory=data_directory))

        # ADB core can always be used
        connection_methods.append(ADBCore(log_level=log_level, data_directory=data_directory, serial=main_args.serialsu))
        return connection_methods

    """
    $$$$$$$$$$$$$$$$$
    $ CUSTOM CUSTOM $
    $$$$$$$$$$$$$$$$$
    """

    @staticmethod
    def bt_addr_to_str(bt_addr):
        # type: (BluetoothAddress) -> str
        """ Convert a Bluetooth address (6 bytes) into a human readable format. """
        return ":".join(format(x, "02x") for x in bytearray(bt_addr))

    def parse_bt_addr(self, bt_addr):
        # type: (Any) -> Optional[BluetoothAddress]
        """ Convert Bluetooth address argument and check lengths. """
        addr = bt_addr
        if ":" in addr:
            addr = addr.replace(":", "")

        if len(addr) != 12:
            self.logger.info("BT Address needs to be 6 hex-bytes")
            return None

        # Convert to byte string (little endian)
        try:
            addr = bytearray.fromhex(addr)
        except TypeError:
            self.logger.info("BT Address must consist of only hex digests!")
            return None

        return addr

    # noinspection PyUnusedLocal
    @staticmethod
    def hexdump(data: bytes, begin: int = 0, highlight: bytes = None):
        red = "\x1b[31m"
        green = "\x1b[32m"
        blue = "\x1b[34m"
        reset = "\x1b[0m"
        dump = ''
        for i, byte in enumerate(data):
            if i % 16 == 0:
                dump += '{:08x}: '.format(i + begin)
            abyte = '{:02x} '.format(byte)
            if byte == 0x00 or byte == 0x0a:
                dump += f'{red}{abyte}{reset}'
            elif byte == 0xff:
                dump += f'{green}{abyte}{reset}'
            elif not isprint(byte):
                dump += f'{blue}{abyte}{reset}'
            else:
                dump += f'{reset}{abyte}{reset}'
            if i % 4 == 3:
                dump += ' '
            if i % 16 == 15:
                dump += ' |'
                dump += ''.join(
                    [(f'{reset}{chr(c)}{reset}' if 32 <= c <= 127 else f'{red if c == 0x00 or c == 0x0a else blue}·{reset}') + ('|' if j % 4 == 3 else '')
                     for j, c in enumerate(data[i - 15:i+1])])
                dump += '\n'
        sys.stdout.write(dump)

    @staticmethod
    def options(message: str, choices: [str]) -> int:
        option_string = f"[🍺] {message}\n "
        for i, choice in enumerate(choices):
            option_string += f"\t{i + 1}) {choice}\n"
        option_string += "Choice [1]\n"

        while True:
            selection = input(option_string)
            if selection == "":
                return 0
            try:
                num = int(selection)
            except ValueError:
                continue
            if num <= len(choices):
                return num - 1

    """
    #### Previously Cmd Functions: ####
    """

    @staticmethod
    def getCmdList():
        """ Returns a list of all CLI commands which are defined in this file."""
        return [name for name, obj in inspect.getmembers(InternalBlueCLI, predicate=inspect.isfunction) if name.startswith("do_")]

    def findCmd(self, keyword):
        # type: (str) -> Optional[Type['Cmd']]
        """ Find and return a Cmd subclass for a given keyword. """
        command_list = self.getCmdList()
        matching_cmds = [cmd for cmd in command_list if keyword in cmd]
        if len(matching_cmds) == 0:
            return None
        if len(matching_cmds) > 1:
            self.logger.warning("Multiple commands match: " + str(matching_cmds))
            return None
        return matching_cmds[0]

    def isAddressInSections(self, address, length=0, sectiontype=""):
        # type: (int, int, str) -> bool
        if not self.internalblue.fw:
            return False

        for section in self.internalblue.fw.SECTIONS:
            if (sectiontype.upper() == "ROM" and not section.is_rom) or (
                    sectiontype.upper() == "RAM" and not section.is_ram
            ):
                continue

            if section.start_addr <= address <= section.end_addr:
                if address + length <= section.end_addr:
                    return True
                else:
                    return False
        return False

    def readMem(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        # type: (Address, int, Optional[Any], int, int) -> Optional[bytes]
        return self.internalblue.readMem(
            address, length, progress_log, bytes_done, bytes_total
        )

    def writeMem(self, address, data, progress_log=None, bytes_done=0, bytes_total=0):
        # type: (Address, bytes, Optional[Any], int, int) -> bool
        return self.internalblue.writeMem(
            address, data, progress_log, bytes_done, bytes_total
        )

    def initMemoryImage(self):
        # type: () -> None
        """
        Initially read out a chip's memory, all sections (RAM+ROM).
        :return:
        """

        # initialize the ROM
        bytes_done = 0
        if not os.path.exists(self.memory_image_template_filename):
            self.logger.info("No template found. Need to read ROM sections as well!")
            self.logger.info(
                "Writing chip-specific template to "
                + self.memory_image_template_filename
                + "..."
            )
            bytes_total = sum([s.size() for s in self.internalblue.fw.SECTIONS])
            self.progress_log = self.progress("Initialize internal memory image")
            dumped_sections = {}
            for section in self.internalblue.fw.SECTIONS:
                # pwntools workaround: dump only rom, extend image
                # dd if=/dev/zero bs=10M count=1 >>memdump_xxx_template.bin
                # if section.is_rom:
                dumped_sections[section.start_addr] = bytes(self.readMem(
                    section.start_addr,
                    section.size(),
                    self.progress_log,
                    bytes_done,
                    bytes_total,
                ))
                bytes_done += section.size()
            self.progress_log.success("Received Data: complete")
            self.memory_image = flat(dumped_sections, filler=0x00)
            f = open(self.memory_image_template_filename, "wb")
            f.write(self.memory_image)
            f.close()

        # otherwise read the RAM
        else:
            self.logger.info(
                self.memory_image_template_filename
                + " exists. Updating non-ROM sections!"
            )
            self.memory_image = read(self.memory_image_template_filename)
            self.refreshMemoryImage()

    def refreshMemoryImage(self):
        # type: () -> None
        """
        Update an existing memory dump, only RAM sections.
        :return:
        """
        bytes_done = 0
        bytes_total = sum(
            [s.size() for s in self.internalblue.fw.SECTIONS if not s.is_rom]
        )
        self.progress_log = self.progress("Refresh internal memory image")
        for section in self.internalblue.fw.SECTIONS:
            if not section.is_rom:
                sectiondump = self.readMem(
                    section.start_addr,
                    section.size(),
                    self.progress_log,
                    bytes_done,
                    bytes_total,
                )
                if sectiondump and self.memory_image:
                    self.memory_image = (
                            self.memory_image[0:section.start_addr]
                            + sectiondump
                            + self.memory_image[section.end_addr:]
                    )
                    bytes_done += section.size()
        self.progress_log.success("Received Data: complete")

    def getMemoryImage(self, refresh=False):
        # type: (bool) -> Any
        if self.memory_image is None:
            self.initMemoryImage()
        elif refresh:
            self.refreshMemoryImage()
        return self.memory_image

    def launchRam(self, address):
        return self.internalblue.launchRam(address)

    # noinspection PyUnusedLocal
    def progress(self, message, status='', *args, **kwargs):
        return ProgressLogger(self.logger, message, status, kwargs)

    """
    ###################################################################################
    ###                              Start of commands                              ###
    ###################################################################################
    """

    # noinspection PyUnusedLocal
    def do_exit(self, args):
        """Exit the program."""
        self.internalblue.exit_requested = True
        self.internalblue.shutdown()
        # [IMPORTANT] for you, yes you, reading this:
        # in all Cmd2 commands (functions starting with
        # do_*), `return True` exits the command loop.
        # So if you just want to return that a command
        # exited successfully, return `None` instead.
        # You can see in `do_repeat` that we just check
        # for a return code of `None` to verify everything
        # went fine and there were no errors.
        # Only here, we return True to exit InternalBlue.
        return True

    loglevel_parser = argparse.ArgumentParser()
    loglevel_parser.add_argument('level', help='New log level (CRITICAL, DEBUG, ERROR, INFO, NOTSET, WARN, WARNING)')

    @cmd2.with_argparser(loglevel_parser)
    def do_loglevel(self, args):
        """Change the verbosity of log messages."""
        log_levels = ["CRITICAL", "DEBUG", "ERROR", "INFO", "NOTSET", "WARN", "WARNING"]

        loglevel = args.level
        if loglevel.upper() in log_levels:
            self.internalblue.log_level = loglevel
            self.logger.info("New log level: " + str(self.internalblue.log_level))
            return None
        else:
            self.logger.warning("Not a valid log level: " + loglevel)
            return False

    monitor_parser = argparse.ArgumentParser()
    monitor_parser.add_argument('command', nargs='+', help='One of: start, stop, kill')

    @cmd2.with_argparser(monitor_parser)
    def do_monitor(self, args):
        """Controlling the monitor."""

        class MonitorController(object):
            instance = None

            @staticmethod
            def getMonitorController(internalblue):
                if MonitorController.instance is None:
                    # Encapsulation type: Bluetooth H4 with linux header (99) None:
                    MonitorController.instance = MonitorController.__MonitorController(
                        internalblue, 0xC9
                    )
                return MonitorController.instance

            # noinspection PyPep8Naming,SpellCheckingInspection
            class __MonitorController(object):
                def __init__(self, internalblue, pcap_data_link_type):
                    self.internalblue = internalblue
                    self.running = False
                    self.wireshark_process = None
                    self.poll_timer = None
                    self.pcap_data_link_type = pcap_data_link_type

                def _spawnWireshark(self):
                    # Global Header Values
                    # noinspection PyUnusedLocal
                    PCAP_GLOBAL_HEADER_FMT = "@ I H H i I I I "
                    PCAP_MAGICAL_NUMBER = 2712847316
                    PCAP_MJ_VERN_NUMBER = 2
                    PCAP_MI_VERN_NUMBER = 4
                    PCAP_LOCAL_CORECTIN = 0
                    PCAP_ACCUR_TIMSTAMP = 0
                    PCAP_MAX_LENGTH_CAP = 65535
                    PCAP_DATA_LINK_TYPE = self.pcap_data_link_type

                    pcap_header = struct.pack(
                        "@ I H H i I I I ",
                        PCAP_MAGICAL_NUMBER,
                        PCAP_MJ_VERN_NUMBER,
                        PCAP_MI_VERN_NUMBER,
                        PCAP_LOCAL_CORECTIN,
                        PCAP_ACCUR_TIMSTAMP,
                        PCAP_MAX_LENGTH_CAP,
                        PCAP_DATA_LINK_TYPE,
                    )

                    # On Linux/hcitool we can directly run wireshark -k -i bluetooth0
                    # FIXME move the monitor class to the according cores
                    DEVNULL = open(os.devnull, "wb")
                    # Check if wireshark or wireshark-gtk is installed. If both are
                    # present, default to wireshark.
                    if os.path.isfile("/usr/bin/wireshark"):
                        wireshark_binary = "wireshark"
                    elif os.path.isfile("/usr/bin/wireshark-gtk"):
                        wireshark_binary = "wireshark-gtk"
                    elif os.path.isfile("/Applications/Wireshark.app/Contents/MacOS/Wireshark"):
                        wireshark_binary = "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
                    else:
                        self.internalblue.logger.warning("Wireshark not found!")
                        return False
                    if self.internalblue.__class__.__name__ == "HCICore":
                        wireshark_interface = self.internalblue.interface.replace(
                            "hci", "bluetooth"
                        )
                        self.internalblue.logger.info("Starting Wireshark on interface %s" % wireshark_interface)
                        self.wireshark_process = subprocess.Popen(
                            [wireshark_binary, "-k", "-i", wireshark_interface],
                            stderr=DEVNULL,
                        )
                    else:
                        self.wireshark_process = subprocess.Popen(
                            [wireshark_binary, "-k", "-i", "-"],
                            stdin=subprocess.PIPE,
                            stderr=DEVNULL,
                        )
                        self.wireshark_process.stdin.write(pcap_header)

                    self.poll_timer = Timer(3, self._pollTimer, ())
                    self.poll_timer.start()
                    return True

                def _pollTimer(self):
                    if self.running and self.wireshark_process is not None:
                        if self.wireshark_process.poll() == 0:
                            # Process has ended
                            self.internalblue.logger.debug("_pollTimer: Wireshark has terminated")
                            self.stopMonitor()
                            self.wireshark_process = None
                        else:
                            # schedule new timer
                            self.poll_timer = Timer(3, self._pollTimer, ())
                            self.poll_timer.start()

                def startMonitor(self):
                    if self.running:
                        self.internalblue.logger.warning("HCI Monitor already running!")
                        return False

                    if self.wireshark_process is None:
                        if not self._spawnWireshark():
                            self.internalblue.logger.info("Unable to start HCI Monitor.")
                            return False

                    self.running = True

                    # If we are running on adbcore, we need to forward all HCI packets
                    # to wireshark (-> use an hci callback):
                    if self.internalblue.__class__.__name__ == "ADBCore":
                        self.internalblue.registerHciCallback(self.adbhciCallback)

                    self.internalblue.logger.info("HCI Monitor started.")
                    return None

                def stopMonitor(self):
                    if not self.running:
                        self.internalblue.logger.warning("HCI Monitor is not running!")
                        return False
                    if self.internalblue.__class__.__name__ == "ADBCore":
                        self.internalblue.unregisterHciCallback(self.adbhciCallback)
                    self.running = False
                    self.internalblue.logger.info("HCI Monitor stopped.")
                    return None

                def killMonitor(self):
                    if self.running:
                        self.stopMonitor()
                    if self.poll_timer is not None:
                        self.poll_timer.cancel()
                        self.poll_timer = None
                    if self.wireshark_process is not None:
                        self.internalblue.logger.info("Killing Wireshark process...")
                        try:
                            self.wireshark_process.terminate()
                            self.wireshark_process.wait()
                        except OSError:
                            self.internalblue.logger.warning("Error during wireshark process termination")
                        self.wireshark_process = None

                def adbhciCallback(self, record):
                    # type: (Record) -> None
                    hcipkt, orig_len, inc_len, flags, drops, recvtime = record

                    dummy = b"\x00\x00\x00"  # TODO: Figure out purpose of these fields
                    direction = p8(flags & 0x01)
                    packet = dummy + direction + hcipkt.getRaw()
                    length = len(packet)
                    ts_sec = (
                        recvtime.second
                    )  # + timestamp.minute*60 + timestamp.hour*60*60 #FIXME timestamp not set
                    ts_usec = recvtime.microsecond
                    pcap_packet = (
                            struct.pack("@ I I I I", ts_sec, ts_usec, length, length) + packet
                    )
                    try:
                        self.wireshark_process.stdin.write(pcap_packet)
                        self.wireshark_process.stdin.flush()
                        self.internalblue.logger.debug("HciMonitorController._callback: done")
                    except IOError as e:
                        self.internalblue.logger.warning("HciMonitorController._callback: broken pipe. terminate." f"{e}")
                        self.killMonitor()

        monitorController = MonitorController.getMonitorController(
            self.internalblue
        )

        if args.command[0] == "start":
            monitorController.startMonitor()
        elif args.command[0] == "stop":
            monitorController.stopMonitor()
        elif args.command[0] == "kill":
            monitorController.killMonitor()
        else:
            self.logger.warning("Unknown subcommand: " + str(args.command[0]))

    repeat_parser = argparse.ArgumentParser()
    repeat_parser.add_argument('timeout', type=int, help='idle time (in milliseconds) between repetitions.')
    repeat_parser.add_argument('command', nargs='+', help='Command which shall be repeated.')

    @cmd2.with_argparser(repeat_parser)
    def do_repeat(self, args):
        """Repeat a given command until user stops it."""
        try:
            timeout = int(args.timeout)
        except ValueError:
            self.logger.info("Not a number: " + args.timeout)
            return False

        repcmdline = " ".join(args.command[1:])
        cmdclass = self.findCmd(args.command[0])
        if cmdclass is None:
            self.logger.warning("Unknown command: " + args.command)
            return False

        while True:
            # Check for keypresses by user:
            if select.select([sys.stdin], [], [], 0.0)[0]:
                self.logger.info("Repeat aborted by user!")
                return None

            # instantiate and run cmd
            cmd_instance = getattr(self, cmdclass)
            if not cmd_instance(repcmdline) is None:
                self.logger.warning("Command failed: " + str(cmd_instance))
                return False
            time.sleep(timeout * 0.001)

    dumpmem_parser = argparse.ArgumentParser()
    dumpmem_parser.add_argument('-n', '--norefresh', action='store_true', help='Do not refresh internal memory image before dumping to file.')
    dumpmem_parser.add_argument('-r', '--ram', action='store_true', help='Only dump the two RAM sections.')
    dumpmem_parser.add_argument('-f', '--file', default='memdump.bin', help='Filename of memory dump (default: %(default)s)')
    dumpmem_parser.add_argument('--overwrite', action='store_true')

    @cmd2.with_argparser(dumpmem_parser)
    def do_dumpmem(self, args):
        """Dumps complete memory image into a file."""
        # Store pure RAM image
        if args.ram:
            bytes_total = sum(
                [s.size() for s in self.internalblue.fw.SECTIONS if s.is_ram]
            )
            bytes_done = 0
            self.progress_log = self.progress("Downloading RAM sections...")
            for section in [s for s in self.internalblue.fw.SECTIONS if s.is_ram]:
                filename = args.file + "_" + hex(section.start_addr)
                if os.path.exists(filename):
                    if not (args.overwrite or yesno("Update '%s'?" % filename)):
                        self.logger.info("Skipping section @%s" % hex(section.start_addr))
                        bytes_done += section.size()
                        continue
                ram = self.readMem(
                    section.start_addr,
                    section.size(),
                    self.progress_log,
                    bytes_done,
                    bytes_total,
                )
                f = open(filename, "wb")
                f.write(ram)
                f.close()
                bytes_done += section.size()
            self.progress_log.success("Done")
            return None

        # Get complete memory image
        if os.path.exists(args.file):
            if not (
                    args.overwrite or yesno("Update '%s'?" % os.path.abspath(args.file))
            ):
                return False

        dump = self.getMemoryImage(refresh=not args.norefresh)
        f = open(args.file, "wb")
        f.write(dump)
        f.close()
        self.logger.info("Memory dump saved in '%s'!" % os.path.abspath(args.file))
        return None

    searchmem_parser = argparse.ArgumentParser()
    searchmem_parser.add_argument('-r', '--refresh', action='store_true', help='Refresh internal memory image before searching.')
    searchmem_parser.add_argument('--hex', action='store_true', help='Interpret pattern as hex string (e.g. ff000a20...)')
    searchmem_parser.add_argument('-a', '--address', action='store_true', help='Interpret pattern as address (hex)')
    searchmem_parser.add_argument('-c', '--context', type=auto_int, default=0,
                                  help='Length of the hexdump before and after the matching pattern (default: %(default)s).')
    searchmem_parser.add_argument('pattern', nargs='*', help='Search Pattern')

    @cmd2.with_argparser(searchmem_parser)
    def do_searchmem(self, args):
        """Search a pattern (string or hex) in the memory image."""
        pattern = " ".join(args.pattern)
        highlight = pattern
        if args.hex:
            try:
                pattern = bytearray.fromhex(pattern)
                highlight = pattern
            except TypeError as e:
                self.logger.warning("Search pattern cannot be converted to bytestring: " + str(e))
                return False
        elif args.address:
            pattern = p32(int(pattern, 16))
            highlight = [x for x in pattern if x != "\x00"]

        memimage = self.getMemoryImage(refresh=args.refresh)
        matches = [m.start(0) for m in re.finditer(re.escape(pattern), memimage)]

        # noinspection PyUnusedLocal
        hexdumplen = (len(pattern) + 16) & 0xFFFF0
        for match in matches:
            startaddr = (match & 0xFFFFFFF0) - args.context
            endaddr = (match + len(pattern) + 16 & 0xFFFFFFF0) + args.context
            self.logger.info("Match at 0x%08x:" % match)
            self.hexdump(memimage[startaddr:endaddr], begin=startaddr, highlight=highlight)
        return None

    hexdump_parser = argparse.ArgumentParser()
    hexdump_parser.add_argument('-l', '--length', type=auto_int, default=256, help='Length of the hexdump (default: %(default)s).')
    hexdump_parser.add_argument('-a', '--aligned', action='store_true', help='Access the memory strictly 4-byte aligned.')
    hexdump_parser.add_argument('address', type=auto_int, help='Start address of the hexdump.')

    @cmd2.with_argparser(hexdump_parser)
    def do_hexdump(self, args):
        """Display a hexdump of a specified region in the memory."""
        # if not self.isAddressInSections(args.address, args.length):
        #    answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?" % (args.address, args.length))
        #    if not answer:
        #        return False

        if args.aligned:
            dump = self.internalblue.readMemAligned(args.address, args.length)
        else:
            dump = self.readMem(args.address, args.length)

        if dump is None:
            return False

        # self.logger.hexdump(bytes(dump), begin=args.address)
        self.hexdump(bytes(dump), begin=args.address)
        return None

    telescope_parser = argparse.ArgumentParser()
    telescope_parser.add_argument('-l', '--length', type=auto_int, default=64, help='Length of the telescope dump (default: %(default)s).')
    telescope_parser.add_argument('-d', '--depth', type=auto_int, default=4, help='Depth of the telescope dump (default: %(default)s).')
    telescope_parser.add_argument('address', type=auto_int, help='Start address of the telescope dump.')

    @cmd2.with_argparser(telescope_parser)
    def do_telescope(self, args):
        """Display a specified region in the memory and follow pointers to valid addresses."""

        def telescope(data, depth):
            val = u32(data[0:4])
            if val == 0:
                return [val, ""]
            if depth > 0 and self.isAddressInSections(val, 0x20):
                newdata = self.readMem(val, 0x20)
                recursive_result = telescope(newdata, depth - 1)
                recursive_result.insert(0, val)
                return recursive_result
            else:
                s = ""
                for c in data:
                    if isprint(c):
                        s += c
                    else:
                        break
                return [val, s]

        if not self.isAddressInSections(args.address, args.length):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?"
                % (args.address, args.length)
            )
            if not answer:
                return False

        dump = self.readMem(args.address, args.length + 4)
        if dump is None:
            return False

        for index in range(0, len(dump) - 4, 4):
            chain = telescope(dump[index:], args.depth)
            output = "0x%08x: " % (args.address + index)
            output += " -> ".join(["0x%08x" % x for x in chain[:-1]])
            output += ' "' + chain[-1] + '"'
            self.logger.info(output)
        return None

    disasm_parser = argparse.ArgumentParser()
    disasm_parser.add_argument('-l', '--length', type=auto_int, default=128, help='Length of the disassembly (default: %(default)s).')
    disasm_parser.add_argument('address', type=auto_int, help='Start address of the disassembly.')

    @cmd2.with_argparser(disasm_parser)
    @needs_pwnlib
    def do_disasm(self, args):
        """Display a disassembly of a specified region in the memory."""
        if not self.isAddressInSections(args.address, args.length):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?"
                % (args.address, args.length)
            )
            if not answer:
                return False

        dump = self.readMem(args.address, args.length)

        if dump is None:
            return False
        else:
            # PyCharm thinks disasm wants a str and not bytes
            # so until pwnlib gets type annotations we just trick the type checker to to prevent a false positive
            if TYPE_CHECKING:
                d = str(dump)
            else:
                d = dump
            print(disasm(d, vma=args.address))  # type: ignore
            return None

    writemem_parser = argparse.ArgumentParser()
    writemem_parser.add_argument('--hex', action='store_true', help='Interpret data as hex string (e.g. ff000a20...)')
    writemem_parser.add_argument('--int', action='store_true', help='Interpret data as 32 bit integer (e.g. 0x123)')
    writemem_parser.add_argument('-f', '--file', help='Read data from this file instead.')
    writemem_parser.add_argument('-r', '--repeat', default=1, type=auto_int, help='Number of times to repeat the data (default: %(default)s)')
    writemem_parser.add_argument('address', type=auto_int, help='Destination address')
    writemem_parser.add_argument('data', nargs='*', help='Data as string (or hexstring/integer, see --hex, --int)')

    @cmd2.with_argparser(writemem_parser)
    def do_writemem(self, args):
        """Writes data to a specified memory address."""
        if args.file is not None:
            data = read(args.file)
        elif len(args.data) > 0:
            data = " ".join(args.data)
            if args.hex:
                try:
                    data = bytearray.fromhex(data)
                except TypeError as e:
                    self.logger.warning("Hex string cannot be converted to bytestring: " + str(e))
                    return False
            elif args.int:
                data = p32(auto_int(data))
        else:
            self.writemem_parser.print_usage()
            print("Either data or --file is required!")
            return False

        data = data * args.repeat

        if not self.isAddressInSections(args.address, len(data), sectiontype="RAM"):
            self.logger.warning(
                "Warning: Address 0x%08x (len=0x%x) is not inside a RAM section."
                % (args.address, len(args.data))
            )

        self.progress_log = self.progress("Writing Memory")
        if self.writeMem(
                args.address, data, self.progress_log, bytes_done=0, bytes_total=len(data)
        ):
            self.progress_log.success(
                "Written %d bytes to 0x%08x." % (len(data), args.address)
            )
            return None
        else:
            self.progress_log.failure("Write failed!")
            return False

    writeasm_parser = argparse.ArgumentParser()
    writeasm_parser.add_argument('-d', '--dry', action='store_true', help='Only pass code to the assembler but don\'t write to memory')
    writeasm_parser.add_argument('-f', '--file', help='Open file in text editor, then read assembly from this file.')
    writeasm_parser.add_argument('address', type=auto_int, help='Destination address')
    writeasm_parser.add_argument('code', nargs='*', help='Assembler code as string')

    @cmd2.with_argparser(writeasm_parser)
    @needs_pwnlib
    def do_writeasm(self, args):
        """Writes assembler instructions to a specified memory address."""
        if args.file is not None:
            if not os.path.exists(args.file):
                f = open(args.file, "w")
                f.write("/* Write arm thumb code here.\n")
                f.write(
                    "   Use '@' or '//' for single line comments or C-like block comments. */\n"
                )
                f.write("\n// 0x%08x:\n\n" % args.address)
                f.close()

            editor = os.environ.get("EDITOR", "vim")
            subprocess.call([editor, args.file])

            code = read(args.file)
        elif len(args.code) > 0:
            code = " ".join(args.code)
        else:
            self.writeasm_parser.print_usage()
            print("Either code or --file is required!")
            return False

        try:
            data = asm(code, vma=args.address)
        except PwnlibException:
            return False

        if len(data) > 0:
            self.logger.info(
                "Assembler was successful. Machine code (len = %d bytes) is:"
                % len(data)
            )
            self.hexdump(data, begin=args.address)
        else:
            self.logger.info("Assembler didn't produce any machine code.")
            return False

        if args.dry:
            self.logger.info("This was a dry run. No data written to memory!")
            return None

        if not self.isAddressInSections(args.address, len(data), sectiontype="RAM"):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?"
                % (args.address, len(data))
            )
            if not answer:
                return False

        self.progress_log = self.progress("Writing Memory")
        if self.writeMem(
                args.address, data, self.progress_log, bytes_done=0, bytes_total=len(data)
        ):
            self.progress_log.success(
                "Written %d bytes to 0x%08x." % (len(data), args.address)
            )
            return None
        else:
            self.progress_log.failure("Write failed!")
            return False

    exec_parser = argparse.ArgumentParser()
    exec_parser.add_argument('-d', '--dry', action='store_true', help='Only pass code to the assembler but don\'t write to memory and don\'t execute')
    exec_parser.add_argument('-e', '--edit', action='store_true', help='Edit command before execution')
    exec_parser.add_argument('-a', '--address', type=auto_int, default=0x211800, help='Destination address of the command instructions')
    exec_parser.add_argument('cmd', help='Name of the command to execute (corresponds to file exec_<cmd>.s)')

    @cmd2.with_argparser(exec_parser)
    @needs_pwnlib
    def do_exec(self, args):
        """Writes assembler instructions to RAM and jumps there."""
        filename = self.internalblue.data_directory + "/exec_%s.s" % args.cmd
        if not os.path.exists(filename):
            f = open(filename, "w")
            f.write("/* Write arm thumb code here.\n")
            f.write(
                "   Use '@' or '//' for single line comments or C-like block comments. */\n"
            )
            f.write("\n// Default destination address is 0x%08x:\n\n" % args.addr)
            f.close()
            args.edit = True

        if args.edit:
            editor = os.environ.get("EDITOR", "vim")
            subprocess.call([editor, filename])

        code = read(filename)

        try:
            data = asm(code, vma=args.addr)
        except PwnlibException:
            return False

        if len(data) == 0:
            self.logger.info("Assembler didn't produce any machine code.")
            return False

        if args.edit:
            self.logger.info(
                "Assembler was successful. Machine code (len = %d bytes) is:"
                % len(data)
            )
            self.hexdump(data, begin=args.addr)

        if args.dry:
            self.logger.info("This was a dry run. No data written to memory!")
            return None

        if not self.isAddressInSections(args.addr, len(data), sectiontype="RAM"):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?"
                % (args.addr, len(args.data))
            )
            if not answer:
                return False

        self.progress_log = self.progress("Writing Memory")
        if not self.writeMem(
                args.addr, data, self.progress_log, bytes_done=0, bytes_total=len(data)
        ):
            self.progress_log.failure("Write failed!")
            return False

        self.progress_log.success(
            "Written %d bytes to 0x%08x." % (len(data), args.addr)
        )

        self.progress_log = self.progress("Launching Command")
        if self.launchRam(args.addr):
            self.progress_log.success("launch_ram cmd was sent successfully!")
            return None
        else:
            self.progress_log.failure("Sending launch_ram command failed!")
            return False

    sendhcicmd_parser = argparse.ArgumentParser()
    sendhcicmd_parser.add_argument('cmdcode', type=auto_int, help='The command code (e.g. 0xfc4c for WriteRam).')
    sendhcicmd_parser.add_argument('data', nargs='*', help='Payload as combinations of hexstrings and hex-uint32 (starting with 0x..)')

    @cmd2.with_argparser(sendhcicmd_parser)
    def do_sendhcicmd(self, args):
        """Send an arbitrary HCI command to the BT controller."""
        if args.cmdcode > 0xFFFF:
            self.logger.info("cmdcode needs to be in the range of 0x0000 - 0xffff")
            return False
        data = b""
        for data_part in args.data:
            if data_part[0:2] == "0x":
                data += p32(auto_int(data_part))
            else:
                data += bytearray.fromhex(data_part)
        if not self.internalblue.sendHciCommand(args.cmdcode, data):
            return False

    patch_parser = argparse.ArgumentParser()
    patch_parser.add_argument('--hex', action='store_true', help='Interpret data as hex string (e.g. ff000a20...)')
    patch_parser.add_argument('--int', action='store_true', help='Interpret data as 32 bit integer (e.g. 0x123)')
    patch_parser.add_argument('--asm', action='store_true', help='Interpret data as assembler instruction')
    patch_parser.add_argument('--delete', '-d', action='store_true', help='Delete the specified patch.')
    patch_parser.add_argument('--slot', '-s', type=auto_int, help='Patchram slot to use (0-128)')
    patch_parser.add_argument('--address', '-a', type=auto_int, help='Destination address')
    patch_parser.add_argument('data', nargs='*', help='Data as string (or hexstring/integer/instruction, see --hex, --int, --asm)')

    @cmd2.with_argparser(patch_parser)
    @needs_pwnlib
    def do_patch(self, args):
        """Patches 4 byte of data at a specified ROM address."""
        if args.slot is not None:
            if (
                    args.slot < 0
                    or args.slot > self.internalblue.fw.PATCHRAM_NUMBER_OF_SLOTS
            ):
                self.logger.warning(
                    "Slot has to be in the range 0 to %i!"
                    % self.internalblue.fw.PATCHRAM_NUMBER_OF_SLOTS
                )
                return False

        # Patch Deletion
        if args.delete:
            if args.slot is not None:
                self.logger.info("Deleting patch in slot %d..." % args.slot)
            elif args.address is not None:
                self.logger.info("Deleting patch at address 0x%x..." % args.address)
            else:
                self.logger.warning("Address or Slot number required!")
                return False
            return self.internalblue.disableRomPatch(args.address, args.slot)

        if args.address is None:
            self.logger.warning("Address is required!")
            return False

        if len(args.data) > 0:
            argument_data = " ".join(args.data)
            if args.hex:
                try:
                    data = binascii.unhexlify(argument_data)
                except TypeError as e:
                    self.logger.warning("Data string cannot be converted to hexstring: " + str(e))
                    return False
            elif args.int:
                data = p32(auto_int(argument_data))
            elif args.asm:
                data = asm(argument_data, vma=args.address)
            else:
                self.logger.warning("--hex, --int or --asm are required")
                return
        else:
            self.patch_parser.print_usage()
            print("Data is required!")
            return False

        if len(data) > 4:
            self.logger.warning("Data size is %d bytes. Truncating to 4 byte!" % len(data))
            data = data[0:4]
        if len(data) < 4:
            self.logger.warning("Data size is %d bytes. 0-Padding to 4 byte!" % len(data))
            data = data.ljust(4, b"\x00")

        if args.address is not None and not self.isAddressInSections(
                args.address, len(data), sectiontype="ROM"
        ):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a ROM section. Continue?"
                % (args.address, len(data))
            )
            if not answer:
                return False

        return self.internalblue.patchRom(args.address, data, args.slot)

    sendlmp_parser = argparse.ArgumentParser()
    sendlmp_parser.add_argument('-c', '--conn_handle', type=auto_int,
                                help='Handle of the connection associated with the other device, default is '
                                     'trying to read connection handle (if supported) or setting it to 0x0C.')
    sendlmp_parser.add_argument('-e', '--extended', action='store_true', help='Use extended opcodes (prepend opcode with 0x7F)')
    sendlmp_parser.add_argument('--slave', action='store_true', help='Send as slave (default is master if auto detection fails)')
    sendlmp_parser.add_argument('--master', action='store_true', help='Send as master (override auto detection)')
    sendlmp_parser.add_argument('opcode', type=auto_int, help='Number of the LMP opcode')
    sendlmp_parser.add_argument('-d', '--data', default='', help='Payload as hexstring.')

    @cmd2.with_argparser(sendlmp_parser)
    def do_sendlmp(self, args):
        """Send LMP packet to another device."""
        # initially assume we are master
        is_master = True

        # automatically get the first valid connection handle if not set
        if args.conn_handle is None:
            if hasattr(self.internalblue.fw, "CONNECTION_MAX"):
                for i in range(self.internalblue.fw.CONNECTION_MAX):
                    connection = self.internalblue.readConnectionInformation(
                        cast("ConnectionNumber", i + 1)
                    )
                    if connection is None:
                        continue
                    if (
                            connection.connection_handle != 0
                            and connection.remote_address != b"\x00\x00\x00\x00\x00\x00"
                    ):
                        args.conn_handle = connection.connection_handle
                        is_master = connection.master_of_connection
                        break

        # if still not set, typical connection handles seem to be 0x0b...0x0d
        if args.conn_handle is None:
            args.conn_handle = 0x0C

        # arguments override auto detection
        if args.slave:
            is_master = False
        if args.master:
            is_master = True

        try:
            data = binascii.unhexlify(args.data)
        except TypeError as e:
            self.logger.warning("Data string cannot be converted to hexstring: " + str(e))
            return False

        self.logger.info(
            "Sending op=%d data=%s to connection handle=0x%04x"
            % (args.opcode, data.decode("utf-8"), args.conn_handle)
        )
        return self.internalblue.sendLmpPacket(
            args.opcode, data, is_master, args.conn_handle, extended_op=args.extended
        )

    # noinspection PyUnusedLocal
    def do_fuzzlmp(self, args):
        """Installs a hook to sendlmp that skips checking opcodes and lengths inside firmware. A remaining
        firmware constraint is the buffer allocated by lm_allocLmpBlock (32 bytes)."""
        return None if self.internalblue.fuzzLmp() else False

    sendlcp_parser = argparse.ArgumentParser()
    sendlcp_parser.add_argument('-c', '--conn_index', type=auto_int, help='Connection index, starts at 0 for first connection.')
    sendlcp_parser.add_argument('data', help='Payload as hexstring.')

    @cmd2.with_argparser(sendlcp_parser)
    def do_sendlcp(self, args):
        """Send LCP packet to another device."""
        # if not set, just use 0
        if not args.conn_index:
            args.conn_index = 0

        try:
            data = args.data.decode("hex")
        except TypeError as e:
            self.logger.warning("Data string cannot be converted to hexstring: " + str(e))
            return False

        self.logger.info(
            "Sending data=%s to connection index=0x%04x"
            % (data.encode("hex"), args.conn_index)
        )
        return self.internalblue.sendLcpPacket(
            cast("ConnectionIndex", args.conn_index), data
        )

    info_parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    info_parser.add_argument('type',
                             help='''Type of information:
            device:       General information (BT Name/Address, ADB Serial ID).
            connections:  List of valid entries in the connection structure.
            patchram:     List of patches in the patchram table.
            heap / bloc:  List of BLOC structures (Heap Pools).
                          Optional argument: BLOC index or address for more details.
                          Optional argument: verbose Show verbose information
            queue:        List of QUEU structures (Blocking Queues).
            '''
                             )
    info_parser.add_argument('args', nargs='*', help='Optional arguments for each type.')

    @cmd2.with_argparser(info_parser)
    def do_info(self, args):
        """Display various types of information parsed from live RAM"""

        def infoConnections(_):
            if not hasattr(self.internalblue.fw, "CONNECTION_MAX"):
                self.logger.warning("CONNECTION_MAX not defined in fw.")
                return False

            for i in range(self.internalblue.fw.CONNECTION_MAX):
                connection = self.internalblue.readConnectionInformation(
                    cast("ConnectionNumber", i + 1)
                )
                if connection is None:
                    continue

                self.logger.info("### | Connection ---%02d--- ###" % i)
                self.logger.info("    - Number:            %d" % connection.connection_number)
                self.logger.info(
                    "    - Remote BT address: %s"
                    % self.bt_addr_to_str(connection.remote_address)
                )
                self.logger.info("    - Remote BT name:    %08X" % connection.remote_name_address)
                self.logger.info(
                    "    - Master of Conn.:   %s" % str(connection.master_of_connection)
                )
                self.logger.info("    - Conn. Handle:      0x%X" % connection.connection_handle)
                self.logger.info(
                    "    - Public RAND:       %s" % bytes_to_hex(connection.public_rand)
                )
                # self.logger.info("    - PIN:               %s"     % bytes_to_hex(connection.pin)
                # self.logger.info("    - BT addr for key:   %s"     % bt_addr_to_str(connection.bt_addr_for_key))
                self.logger.info(
                    "    - Effective Key Len: %d byte (%d bit)"
                    % (connection.effective_key_len, 8 * connection["effective_key_len"])
                )
                self.logger.info("    - Link Key:          %s" % bytes_to_hex(connection.link_key))
                self.logger.info(
                    "    - LMP Features:      %s"
                    % bytes_to_hex(connection.extended_lmp_feat)
                )
                self.logger.info(
                    "    - Host Supported F:  %s"
                    % bytes_to_hex(connection.host_supported_feat)
                )
                self.logger.info("    - TX Power (dBm):    %d" % connection.tx_pwr_lvl_dBm)
                self.logger.info("    - Array Index:       %s" % bytes_to_hex(connection.id))
            print()
            return None

        def infoDevice(_):
            for const in ["BD_ADDR", "DEVICE_NAME"]:
                if const not in dir(self.internalblue.fw):
                    self.logger.warning(" '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                    return False
            bt_addr = self.readMem(self.internalblue.fw.BD_ADDR, 6)[::-1]
            bt_addr_str = self.bt_addr_to_str(bt_addr)
            device_name = self.readMem(self.internalblue.fw.DEVICE_NAME, 258)
            device_name_len = device_name[0] - 1
            device_name = device_name[2: 2 + device_name_len]
            adb_serial = self.internalblue.interface

            self.logger.info("### | Device ###")
            self.logger.info("    - Name:       %s" % device_name.decode("utf-8"))
            self.logger.info("    - ADB Serial: %s" % adb_serial)
            self.logger.info("    - Address:    %s" % bt_addr_str)
            return None

        @needs_pwnlib
        def infoPatchram(_):
            if not hasattr(self.internalblue.fw, "PATCHRAM_NUMBER_OF_SLOTS"):
                self.logger.warning("PATCHRAM_NUMBER_OF_SLOTS not defined in fw.")
                return False

            # try:
            (
                table_addresses,
                table_values,
                table_slots,
            ) = self.internalblue.getPatchramState()
            # except:
            #    self.logger.info("Invalid Patchram Table")
            #    return False

            self.logger.info("### | Patchram Table ###")
            for i in range(self.internalblue.fw.PATCHRAM_NUMBER_OF_SLOTS):
                if table_slots[i] == 1:
                    code = disasm(
                        table_values[i], vma=table_addresses[i], byte=False, offset=False
                    )
                    code = code.replace("    ", " ").replace("\n", ";  ")
                    self.logger.info(
                        "[%03d] 0x%08X: %s (%s)"
                        % (i, table_addresses[i], bytes_to_hex(table_values[i]), code)
                    )
            return None

        def infoHeap(info_args):
            bloc_for_details = None
            bloc_address = None
            bloc_index = None
            verbose = False
            for ar in info_args:
                try:
                    if ar in ["verbose"]:
                        verbose = True
                    elif info_args[0].startswith("0x"):
                        bloc_address = int(info_args[0], 16)
                    else:
                        bloc_index = int(info_args[0])
                except TypeError:
                    self.logger.warning(
                        "Optional argument is neither a number (decimal) nor an address (hex) nor -v"
                    )
                    return False

            progress_log = self.progress("Traversing Heap")
            heaplist = self.internalblue.readHeapInformation()  # List of BLOC structs

            if not heaplist:
                self.logger.debug("No heap returned!")
                progress_log.failure("empty")
                return False

            # Print Bloc Buffer Table
            self.logger.info("  [ Idx ] @Pool-Addr  Buf-Size  Avail/Capacity  Mem-Size @ Addr")
            self.logger.info("  -----------------------------------------------------------------")
            for heappool in heaplist:
                # TODO: waitlist

                marker_str = "> "
                if bloc_address is not None and heappool["address"] == bloc_address:
                    bloc_for_details = heappool
                elif bloc_index is not None and heappool["index"] == bloc_index:
                    bloc_for_details = heappool
                else:
                    marker_str = "  "

                self.logger.info(
                    marker_str
                    + (
                        "BLOC[{index}] @ 0x{address:06X}: {buffer_size:8d}"
                        "    {list_length:2d} / {capacity:2d}        "
                        "{memory_size:7d} @ 0x{memory:06X}"
                    ).format(**heappool)
                )

                # Print verbose heap information
                if verbose:
                    if hasattr(self.internalblue.fw, "BLOC_NG"):
                        self.logger.warning(
                            "            Corruption warning might be wrong for allocated buffers!"
                        )

                    self.logger.info("            Buffer   : Header    Status")
                    self.logger.info("            -------------------------------")
                    for buff in sorted(heappool["buffer_headers"].keys()):
                        hdr = heappool["buffer_headers"][buff]
                        info = "            0x%06x : 0x%06x  " % (buff, hdr)
                        if hdr in heappool["buffer_headers"] or hdr == 0:
                            info += "Free"
                        elif hdr == heappool["address"]:
                            info += "Used"
                        else:
                            info += "\033[;31mCorrupted\033[;00m"

                        if buff == heappool["buffer_list"]:
                            info += " / List Head"

                        self.logger.info(info)
                    self.logger.info("")

            # Print Bloc Buffer Details
            if bloc_for_details is None:
                progress_log.success("done")
                return None

            # Print Buffer Details
            buffer_size = bloc_for_details["buffer_size"] + 4
            for buffer_address, buffer_hdr in bloc_for_details["buffer_headers"].items():
                progress_log.status(
                    "Dumping buffers from BLOC[%d]: 0x%06X"
                    % (bloc_for_details["index"], buffer_address)
                )
                # Buffer in use!
                if buffer_hdr == bloc_for_details["address"]:
                    buf = self.internalblue.readMem(buffer_address, buffer_size)
                    self.logger.info(
                        "dumping buffer 0x%06X from BLOC[%d]:"
                        % (buffer_address + 4, bloc_for_details["index"])
                    )
                    self.hexdump(buf[4:], begin=buffer_address + 4)

            progress_log.success("done")
            return None

        def infoQueue(_):
            progress_log = self.progress("Traversing Queues")
            queuelist = self.internalblue.readQueueInformation()  # List of QUEU structs

            if queuelist is None:
                self.logger.debug("No queues returned!")
                progress_log.failure("empty")
                return False

            self.logger.info(
                "[ Idx  ] @Queue-Addr  Queue-Name          Items/Free/Capacity  Item-Size  Buffer"
            )
            self.logger.info(
                "--------------------------------------------------------------------------------"
            )
            for queue in [vars(element) for element in queuelist]:
                # TODO: waitlist
                self.logger.info(
                    (
                        "QUEU[{index:2d}] @ 0x{address:06X}:  {name:21s} {available_items:2d} /"
                        " {free_slots:2d} / {capacity:2d}      {item_size:2d} Bytes    0x{queue_buf_start:06X}"
                    ).format(**queue)
                )

            # TODO: output all queued items
            # if "-v" in args:
            #    print
            #    for queue in queuelist:
            #        if len(queue["items"]) > 0:
            #            self.logger.info("QUEUE[{index}] @ 0x{address:06X}:  {name:10s}  ({available_items:d} items)\n"
            #                     "---------------------------------------------------------------------------")
            #            for item in queue["items"]:
            #                self.hexdump(item, begin=0x0)

            progress_log.success("done")
            return None

        subcommands = {
            "connections": infoConnections,
            "device": infoDevice,
            "patchram": infoPatchram,
            "heap": infoHeap,
            "bloc": infoHeap,
            "queue": infoQueue,
        }

        if args.type in subcommands:
            return subcommands[args.type](args.args)
        else:
            self.logger.warning(
                "Unknown type: %s\nKnown types: %s"
                % (args.type, list(subcommands.keys()))
            )
            return False

    tracepoint_parser = argparse.ArgumentParser()
    tracepoint_parser.add_argument('command', help='One of: add/set, remove/delete/del, list/show')
    tracepoint_parser.add_argument('address', type=auto_int, nargs='?', help='Address of the tracepoint')

    @cmd2.with_argparser(tracepoint_parser)
    def do_tracepoint(self, args):
        """Manage tracepoints."""
        if args.command in ["add", "set"]:
            if args.address is None:
                self.logger.warning("Missing address. Use tracepoint add <address>")
                return False
            self.logger.info("Inserting tracepoint at 0x%x..." % args.address)
            if self.internalblue.addTracepoint(args.address):
                self.logger.info("Tracing instruction at address 0x%x." % args.address)
            else:
                return False

        elif args.command in ["remove", "delete", "del"]:
            if args.address is None:
                self.logger.warning("Missing address. Use tracepoint del <address>")
                return False
            self.logger.info("Deleting tracepoint at 0x%x..." % args.address)
            if not self.internalblue.deleteTracepoint(args.address):
                return False
            self.logger.info("Deleted tracepoint at address 0x%x" % args.address)

        elif args.command in ["list", "show"]:
            if len(self.internalblue.tracepoints) == 0:
                self.logger.info("No active tracepoints.")
            else:
                tracepoints = "\n".join(
                    ["  - 0x%x" % tp[0] for tp in self.internalblue.tracepoints]
                )
                self.logger.info("Active Tracepoints:\n" + tracepoints)

    breakpoint_parser = argparse.ArgumentParser()
    breakpoint_parser.add_argument('address', type=auto_int, help='Address of the breakpoint')

    @cmd2.with_argparser(breakpoint_parser)
    def do_breakpoint(self, args):
        """Add breakpoint. This will crash, but produces a stackdump at the given address."""
        self.logger.info("Inserting breakpoint at 0x%x..." % args.address)
        self.internalblue.patchRom(args.address, b'\x00\xbe\x00\x00')  # on ARM, hex code for a break point is 0xBE00

    def do_memorypool(self, _):
        """Enable memory pool statistics."""
        self.logger.info("Memory statistics will now appear every second.")
        self.internalblue.sendHciCommand(HCI_COMND.VSC_DBFW, b'\x50')

    connect_parser = argparse.ArgumentParser()
    connect_parser.add_argument('btaddr', help='Bluetooth address of the remote device (with or without \':\').')

    @cmd2.with_argparser(connect_parser)
    def do_connect(self, args):
        """Initiate a connection to a remote Bluetooth device"""
        addr = self.parse_bt_addr(args.btaddr)
        if not addr:
            return False
        self.internalblue.connectToRemoteDevice(addr)

    connectle_parser = argparse.ArgumentParser()
    connectle_parser.add_argument('--addrtype', type=auto_int, default=0,
                                  help="Address type: Public Device (0, default), Random Device (1), Public Identity (2), Random static Identity (3)")
    connectle_parser.add_argument('btaddr', help="Bluetooth address of the remote device (with or without ':'.")

    @cmd2.with_argparser(connectle_parser)
    def do_connectle(self, args):
        """Initiate a connection to a remote LE Bluetooth device"""
        addr = self.parse_bt_addr(args.btaddr)
        if not addr:
            return False
        self.internalblue.connectToRemoteLEDevice(addr, args.addrtype)

    readafh_parser = argparse.ArgumentParser()
    readafh_parser.add_argument('-c', '--conn_handle', type=auto_int,
                                help='Handle of the connection associated with the other device, default is trying to read all connection handles '
                                     '(if supported) or setting it to 0x0C.')

    @cmd2.with_argparser(readafh_parser)
    def do_readafh(self, args):
        """Read adaptive frequency hopping (AFH) channel map."""

        def readafh(handle):
            """ This is a standard HCI command but might be useful when playing around with the physical layer.
            """
            response = self.internalblue.sendHciCommand(
                HCI_COMND.Read_AFH_Channel_Map, p16(handle)
            )

            if len(response) < 17 or response[8:] == b"\x00" * 9:
                self.logger.info("Connection 0x%04x is not established." % handle)
                return False

            self.logger.info("Connection Handle: 0x%04x" % handle)
            self.logger.info("AFH Enabled: %s" % bool(response[7] != 0))
            channels = ""
            for c in response[8:]:
                bits = format(c, "08b")
                for b in bits:
                    if b == "1":
                        channels = channels + " *"
                    else:
                        channels = channels + "  "

            map_string = "AFH Channel Map:\n     0 1 2 3 4 5 6 7 8 9\n"
            map_string += "00: " + channels[0:20] + "\n"
            map_string += "10: " + channels[20:40] + "\n"
            map_string += "20: " + channels[40:60] + "\n"
            map_string += "30: " + channels[60:80] + "\n"
            map_string += "40: " + channels[80:100] + "\n"
            map_string += "50: " + channels[100:120] + "\n"
            map_string += "60: " + channels[120:140] + "\n"
            map_string += "70: " + channels[140:158] + "\n"

            self.logger.info(map_string)
            return None

        if args.conn_handle is None:
            # automatically get all connection handles if not set
            if hasattr(self.internalblue.fw, "CONNECTION_MAX"):
                for i in range(self.internalblue.fw.CONNECTION_MAX):
                    connection = self.internalblue.readConnectionInformation(
                        cast("ConnectionNumber", i + 1)
                    )
                    if connection is None:
                        continue
                    else:
                        readafh(connection.connection_handle)
                return None
            # if not set but connection struct unknown, typical connection handles seem to be 0x0b...0x0d
            else:
                return readafh(0x0C)

        return readafh(args.conn_handle)

    diag_parser = argparse.ArgumentParser()
    diag_parser.add_argument("--type", type=auto_int, default=0x07,
                             help="Type. Default is 0x07, but you can use 0x02 for ACL and 0x03 for SCO. Other values might crash.")
    diag_parser.add_argument("data", nargs="*",
                             help="Payload as combinations of hexstrings and hex-uint32 (starting with 0x..). "
                                  "Known commands so far: Reset ACL BR Stats (b9), Get ACL BR Stats (c1), "
                                  "Get ACL EDR Stats (c2), Get AUX Stats (c3), Get Connections (cf), "
                                  "Enable Link Manager Diagnostics (f001), Get Memory Peek (f1), Get Memory Poke (f2), "
                                  "Get Memory Dump (f3), Packet Test (f6).",
                             )

    @cmd2.with_argparser(diag_parser)
    def do_diag(self, args):
        """Send an arbitrary Broadcom H4 diagnostic command to the BT controller."""
        data = b""
        for data_part in args.data:
            if data_part[0:2] == "0x":
                data += p32(auto_int(data_part))
            else:
                try:
                    data += binascii.unhexlify(data_part)
                # might return odd length string etc.
                except binascii.Error:
                    self.logger.warning("Invalid hex string!")
                    return False
        self.internalblue.sendH4(args.type, data)

    launch_parser = argparse.ArgumentParser()
    launch_parser.add_argument('address', type=auto_int, help='Execute this address.')

    @cmd2.with_argparser(launch_parser)
    def do_launch(self, args):
        """Executes launch RAM HCI command. Note that this causes threading issues on some chips."""
        self.internalblue.launchRam(args.address)
        return None

    def do_adv(self, _):
        """Enables enhanced advertisement reports in the first half of the `Event Type` field."""
        self.internalblue.enableEnhancedAdvReport()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--data-directory", help="Set data directory. Default: ~/.internalblue")
    parser.add_argument("-v", "--verbose", help="Set log level to DEBUG", action="store_true")
    parser.add_argument("-i", "--ios-device",
                        help="Tell internalblue to connect to a remote iPhone HCI socket. Specify socket IP address and port (i.e., 172.20.10.1:1234).")
    parser.add_argument("-s", "--serialsu", action="store_true",
                        help="On ADB, directly try su/serial/busybox scripting, if you do not have a special bluetooth.default.so file.")
    parser.add_argument("--trace", help="Trace hci connection")
    parser.add_argument("--device", help="Specify device/core to be used")
    parser.add_argument("-c", "--commands", help="CLI command to run before prompting, separated by ';' (used for easier testing)")
    parser.add_argument("--replay", help="Intercept and replace every communication with the core with the one in the specified file")
    parser.add_argument("--save", help="Store a trace into the file that can be used with --replay")
    return parser.parse_known_args()


def internalblue_entry_point():
    arg, unknown_args = parse_args()
    sys.argv = sys.argv[:1] + unknown_args
    cli = InternalBlueCLI(arg)
    sys.exit(cli.cmdloop())


if __name__ == "__main__":
    internalblue_entry_point()
