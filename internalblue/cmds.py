#!/usr/bin/env python2

# cmds.py
#
# All available CLI commands are defined in this file by
# creating subclasses of the Cmd class.
#
# Copyright (c) 2018 Dennis Mantz. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,version
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

import binascii
import re
from builtins import str
from builtins import hex
from builtins import range
from builtins import object
import os
import sys
import inspect
import argparse
import subprocess
from threading import Timer
import textwrap
import struct
import time
import select
import json

from pwnlib.context import context
from pwnlib.asm import disasm, asm
from pwnlib.exception import PwnlibException
from pwnlib.log import Progress
from pwnlib.ui import yesno
from pwnlib.util.fiddling import isprint

from internalblue.utils.pwnlib_wrapper import log, flat, read, p8, p32, u32, p16
from internalblue.utils import bytes_to_hex
from internalblue.hci import HCI_COMND


from typing import List, Optional, Any, TYPE_CHECKING, Type, cast

if TYPE_CHECKING:
    from internalblue.core import InternalBlue
    from internalblue import Record, BluetoothAddress, Address


def getCmdList() -> List[Type["Cmd"]]:
    """ Returns a list of all commands which are defined in this cmds.py file.
    This is done by searching for all subclasses of Cmd
    """
    return [
        obj
        for name, obj in inspect.getmembers(sys.modules[__name__])
        if inspect.isclass(obj) and issubclass(obj, Cmd)
    ][1:]


def findCmd(keyword):
    # type: (str) -> Optional[Type['Cmd']]
    """ Find and return a Cmd subclass for a given keyword.
    """
    command_list = getCmdList()
    matching_cmds = [cmd for cmd in command_list if keyword in cmd.keywords]
    if len(matching_cmds) == 0:
        return None
    if len(matching_cmds) > 1:
        log.warn("Multiple commands match: " + str(matching_cmds))
        return None
    return matching_cmds[0]


def auto_int(x):
    """ Convert a string (either decimal number or hex number) into an integer.
    """
    return int(x, 0)


def bt_addr_to_str(bt_addr):
    # type: (BluetoothAddress) -> str
    """ Convert a Bluetooth address (6 bytes) into a human readable format.
    """
    return ":".join(format(x, "02x") for x in bytearray(bt_addr))


def parse_bt_addr(bt_addr):
    # type: (Any) -> Optional[BluetoothAddress]
    """ Convert Bluetooth address argument and check lengths.
    """
    addr = bt_addr
    if ":" in addr:
        addr = addr.replace(":", "")

    if len(addr) != 12:
        log.info("BT Address needs to be 6 hex-bytes")
        return None

    # Convert to byte string (little endian)
    try:
        addr = bytearray.fromhex(addr)
    except TypeError:
        log.info("BT Address must consist of only hex digests!")
        return None

    return addr


class Cmd(object):
    """ This class is the superclass of a CLI command. Every CLI command
    must be defined as subclass of Cmd. The subclass must define the
    'keywords' list as member variable. The actual implementation of the
    command should be located in the work() method.
    """

    description: str
    parser: argparse.ArgumentParser
    keywords: List[str] = []
    aborted: bool
    progress_log: Optional[Progress]
    memory_image: Optional[bytes] = None

    def __init__(self, cmdline: str, internalblue: 'InternalBlue') -> None:
        self.cmdline = cmdline
        self.internalblue = internalblue
        self.memory_image_template_filename = (
            internalblue.data_directory + "/memdump__template.bin"
        )
        if self.internalblue.fw:
            self.memory_image_template_filename = (
                internalblue.data_directory
                + "/memdump_"
                + self.internalblue.fw.__name__[6:12]
                + "_template.bin"
            )

    def __str__(self):
        return self.cmdline

    def work(self) -> bool:
        return True

    def abort_cmd(self) -> None:
        self.aborted = True
        if hasattr(self, "progress_log"):
            self.progress_log.failure("Command aborted")

    def getArgs(self) -> Optional[argparse.Namespace]:
        try:
            return self.parser.parse_args(self.cmdline.split(" ")[1:])
        except SystemExit:
            return None

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
        bytes_done = 0
        if not os.path.exists(self.memory_image_template_filename):
            log.info("No template found. Need to read ROM sections as well!")
            log.info(
                "Writing chip-specific template to "
                + self.memory_image_template_filename
                + "..."
            )
            bytes_total = sum([s.size() for s in self.internalblue.fw.SECTIONS])
            self.progress_log = log.progress("Initialize internal memory image")
            dumped_sections = {}
            for section in self.internalblue.fw.SECTIONS:
                dumped_sections[section.start_addr] = self.readMem(
                    section.start_addr,
                    section.size(),
                    self.progress_log,
                    bytes_done,
                    bytes_total,
                )
                bytes_done += section.size()
            self.progress_log.success("Received Data: complete")
            Cmd.memory_image = flat(dumped_sections, filler="\x00")
            f = open(self.memory_image_template_filename, "wb")
            f.write(Cmd.memory_image)
            f.close()
        else:
            log.info(
                self.memory_image_template_filename
                + " already exists. Only read and updating non-ROM sections!"
            )
            Cmd.memory_image = read(self.memory_image_template_filename)
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
        self.progress_log = log.progress("Refresh internal memory image")
        for section in self.internalblue.fw.SECTIONS:
            if not section.is_rom:
                sectiondump = self.readMem(
                    section.start_addr,
                    section.size(),
                    self.progress_log,
                    bytes_done,
                    bytes_total,
                )
                if sectiondump and Cmd.memory_image:
                    Cmd.memory_image = (
                        Cmd.memory_image[0 : section.start_addr]
                        + sectiondump
                        + Cmd.memory_image[section.end_addr :]
                    )
                    bytes_done += section.size()
        self.progress_log.success("Received Data: complete")

    def getMemoryImage(self, refresh=False):
        # type: (bool) -> Any
        if Cmd.memory_image is None:
            self.initMemoryImage()
        elif refresh:
            self.refreshMemoryImage()
        return Cmd.memory_image

    def launchRam(self, address):
        return self.internalblue.launchRam(address)


#
# Start of implemented commands:
#


class CmdHelp(Cmd):
    keywords = ["help", "?"]
    description = (
        "Display available commands. Use help <cmd> to display command specific help."
    )

    def work(self):
        args = self.cmdline.split(" ")
        command_list = getCmdList()
        if len(args) > 1:
            cmd = findCmd(args[1])
            if cmd is None:
                log.info("No command with the name: " + args[1])
                return True
            if hasattr(cmd, "parser"):
                cmd.parser.print_help()
            else:
                print(cmd.description)
                print("Aliases: " + " ".join(cmd.keywords))
        else:
            for cmd in command_list:
                print(
                    cmd.keywords[0].ljust(15)
                    + ("\n" + " " * 15).join(textwrap.wrap(cmd.description, 60))
                )
        return True


class CmdExit(Cmd):
    keywords = ["exit", "quit", "q", "bye"]
    description = "Exit the program."

    def work(self):
        self.internalblue.exit_requested = True
        return True


class CmdIPython(Cmd):
    keywords = ["ipython"]
    description = "Drop into an IPython shell (for debugging internalblue)"

    def work(self):
        print(
            "\n\tDropping into IPython shell!\n\tUse 'self.internalblue' to access the framework."
        )
        print("\tUse 'quit' or 'exit' to return to the InternalBlue CLI.\n")
        try:
            from IPython import embed

            embed()
        except Exception as e:
            log.warn("Error when dropping into IPython shell: " + str(e))
        return True


class CmdLogLevel(Cmd):
    keywords = ["log_level", "loglevel", "verbosity"]
    description = "Change the verbosity of log messages."
    log_levels = ["CRITICAL", "DEBUG", "ERROR", "INFO", "NOTSET", "WARN", "WARNING"]

    for keyword in list(keywords):
        for log_level in log_levels:
            keywords.append("%s %s" % (keyword, log_level))

    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument("level", help="New log level (%s)" % ", ".join(log_levels))

    def work(self):
        args = self.getArgs()
        if args is None:
            return True
        loglevel = args.level
        if loglevel.upper() in self.log_levels:
            context.log_level = loglevel
            self.internalblue.log_level = loglevel
            log.info("New log level: " + str(context.log_level))
            return True
        else:
            log.warn("Not a valid log level: " + loglevel)
            return False


class CmdMonitor(Cmd):
    keywords = ["monitor", "wireshark"]
    description = "Controlling the monitor."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument("command", help="One of: start, stop, kill")

    class MonitorController(object):
        instance = None

        @staticmethod
        def getMonitorController(internalblue):
            if CmdMonitor.MonitorController.instance is None:
                # Encapsulation type: Bluetooth H4 with linux header (99) None:
                CmdMonitor.MonitorController.instance = CmdMonitor.MonitorController.__MonitorController(
                    internalblue, 0xC9
                )
            return CmdMonitor.MonitorController.instance

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
                else:
                    log.warn("Wireshark not found!")
                    return False
                if self.internalblue.__class__.__name__ == "HCICore":
                    wireshark_interface = self.internalblue.interface.replace(
                        "hci", "bluetooth"
                    )
                    log.info("Starting Wireshark on interface %s" % wireshark_interface)
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
                        log.debug("_pollTimer: Wireshark has terminated")
                        self.stopMonitor()
                        self.wireshark_process = None
                    else:
                        # schedule new timer
                        self.poll_timer = Timer(3, self._pollTimer, ())
                        self.poll_timer.start()

            def startMonitor(self):
                if self.running:
                    log.warn("HCI Monitor already running!")
                    return False

                if self.wireshark_process is None:
                    if not self._spawnWireshark():
                        log.info("Unable to start HCI Monitor.")
                        return False

                self.running = True

                # If we are running on adbcore, we need to forward all HCI packets
                # to wireshark (-> use an hci callback):
                if self.internalblue.__class__.__name__ == "ADBCore":
                    self.internalblue.registerHciCallback(self.adbhciCallback)

                log.info("HCI Monitor started.")
                return True

            def stopMonitor(self):
                if not self.running:
                    log.warn("HCI Monitor is not running!")
                    return False
                if self.internalblue.__class__.__name__ == "ADBCore":
                    self.internalblue.unregisterHciCallback(self.adbhciCallback)
                self.running = False
                log.info("HCI Monitor stopped.")
                return True

            def killMonitor(self):
                if self.running:
                    self.stopMonitor()
                if self.poll_timer is not None:
                    self.poll_timer.cancel()
                    self.poll_timer = None
                if self.wireshark_process is not None:
                    log.info("Killing Wireshark process...")
                    try:
                        self.wireshark_process.terminate()
                        self.wireshark_process.wait()
                    except OSError:
                        log.warn("Error during wireshark process termination")
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
                    log.debug("HciMonitorController._callback: done")
                except IOError as e:
                    log.warn(
                        "HciMonitorController._callback: broken pipe. terminate." f"{e}"
                    )
                    self.killMonitor()

    def work(self):
        args = self.getArgs()
        if not args:
            return True

        monitorController = CmdMonitor.MonitorController.getMonitorController(
            self.internalblue
        )

        if args.command == "start":
            monitorController.startMonitor()
        elif args.command == "stop":
            monitorController.stopMonitor()
        elif args.command == "kill":
            monitorController.killMonitor()
        else:
            log.warn("Unknown subcommand: " + args.command)
            return False
        return True


class CmdRepeat(Cmd):
    keywords = ["repeat", "watch"]
    description = "Repeat a given command until user stops it."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "timeout", type=int, help="idle time (in milliseconds) between repetitions."
    )
    parser.add_argument("command", help="Command which shall be repeated.")

    def work(self):
        args = self.cmdline.split(" ")
        if len(args) < 3:
            log.info("Need more arguments!")
            return False

        try:
            timeout = int(args[1])
        except ValueError:
            log.info("Not a number: " + args[1])
            return False

        repcmdline = " ".join(args[2:])
        cmdclass = findCmd(args[2])

        if cmdclass is None:
            log.warn("Unknown command: " + args[2])
            return False

        while True:
            # Check for keypresses by user:
            if select.select([sys.stdin], [], [], 0.0)[0]:
                log.info("Repeat aborted by user!")
                return True

            # instanciate and run cmd
            cmd_instance = cmdclass(repcmdline, self.internalblue)
            if not cmd_instance.work():
                log.warn("Command failed: " + str(cmd_instance))
                return False
            time.sleep(timeout * 0.001)


class CmdDumpMem(Cmd):
    keywords = ["dumpmem", "memdump"]
    description = "Dumps complete memory image into a file."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--norefresh",
        "-n",
        action="store_true",
        help="Do not refresh internal memory image before dumping to file.",
    )
    parser.add_argument(
        "--ram", "-r", action="store_true", help="Only dump the two RAM sections."
    )
    parser.add_argument(
        "--file",
        "-f",
        default="memdump.bin",
        help="Filename of memory dump (default: %(default)s)",
    )
    parser.add_argument("--overwrite", action="store_true")

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        # Store pure RAM image
        if args.ram:
            bytes_total = sum(
                [s.size() for s in self.internalblue.fw.SECTIONS if s.is_ram]
            )
            bytes_done = 0
            self.progress_log = log.progress("Downloading RAM sections...")
            for section in [s for s in self.internalblue.fw.SECTIONS if s.is_ram]:
                filename = args.file + "_" + hex(section.start_addr)
                if os.path.exists(filename):
                    if not (args.overwrite or yesno("Update '%s'?" % filename)):
                        log.info("Skipping section @%s" % hex(section.start_addr))
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
            return True

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
        log.info("Memory dump saved in '%s'!" % os.path.abspath(args.file))
        return True


class CmdSearchMem(Cmd):
    keywords = ["searchmem", "memsearch"]
    description = "Search a pattern (string or hex) in the memory image."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--refresh",
        "-r",
        action="store_true",
        help="Refresh internal memory image before searching.",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="Interpret pattern as hex string (e.g. ff000a20...)",
    )
    parser.add_argument(
        "--address",
        "-a",
        action="store_true",
        help="Interpret pattern as address (hex)",
    )
    parser.add_argument(
        "--context",
        "-c",
        type=auto_int,
        default=0,
        help="Length of the hexdump before and after the matching pattern (default: %(default)s).",
    )
    parser.add_argument("pattern", nargs="*", help="Search Pattern")

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        pattern = " ".join(args.pattern)
        highlight = pattern
        if args.hex:
            try:
                pattern = bytearray.fromhex(pattern)
                highlight = pattern
            except TypeError as e:
                log.warn("Search pattern cannot be converted to bytestring: " + str(e))
                return False
        elif args.address:
            pattern = p32(int(pattern, 16))
            highlight = [x for x in pattern if x != "\x00"]

        memimage = self.getMemoryImage(refresh=args.refresh)
        matches = [m.start(0) for m in re.finditer(re.escape(pattern), memimage)]

        hexdumplen = (len(pattern) + 16) & 0xFFFF0
        for match in matches:
            startadr = (match & 0xFFFFFFF0) - args.context
            endadr = (match + len(pattern) + 16 & 0xFFFFFFF0) + args.context
            log.info("Match at 0x%08x:" % match)
            log.hexdump(memimage[startadr:endadr], begin=startadr, highlight=highlight)
        return True


class CmdHexdump(Cmd):
    keywords = ["hexdump", "hd", "readmem"]
    description = "Display a hexdump of a specified region in the memory."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--length",
        "-l",
        type=auto_int,
        default=256,
        help="Length of the hexdump (default: %(default)s).",
    )
    parser.add_argument(
        "--aligned",
        "-a",
        action="store_true",
        help="Access the memory strictly 4-byte aligned.",
    )
    parser.add_argument("address", type=auto_int, help="Start address of the hexdump.")

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        # if not self.isAddressInSections(args.address, args.length):
        #    answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?" % (args.address, args.length))
        #    if not answer:
        #        return False

        dump = None
        if args.aligned:
            dump = self.internalblue.readMemAligned(args.address, args.length)
        else:
            dump = self.readMem(args.address, args.length)

        if dump is None:
            return False

        log.hexdump(bytes(dump), begin=args.address)
        return True


class CmdTelescope(Cmd):
    keywords = ["telescope", "tel"]
    description = "Display a specified region in the memory and follow pointers to valid addresses."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--length",
        "-l",
        type=auto_int,
        default=64,
        help="Length of the telescope dump (default: %(default)s).",
    )
    parser.add_argument(
        "--depth",
        "-d",
        type=auto_int,
        default=4,
        help="Depth of the telescope dump (default: %(default)s).",
    )
    parser.add_argument(
        "address", type=auto_int, help="Start address of the telescope dump."
    )

    def telescope(self, data, depth):
        val = u32(data[0:4])
        if val == 0:
            return [val, ""]
        if depth > 0 and self.isAddressInSections(val, 0x20):
            newdata = self.readMem(val, 0x20)
            recursive_result = self.telescope(newdata, depth - 1)
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

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

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
            chain = self.telescope(dump[index:], args.depth)
            output = "0x%08x: " % (args.address + index)
            output += " -> ".join(["0x%08x" % x for x in chain[:-1]])
            output += ' "' + chain[-1] + '"'
            log.info(output)
        return True


class CmdDisasm(Cmd):
    keywords = ["disasm", "disas", "disassemble", "d"]
    description = "Display a disassembly of a specified region in the memory."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--length",
        "-l",
        type=auto_int,
        default=128,
        help="Length of the disassembly (default: %(default)s).",
    )
    parser.add_argument(
        "address", type=auto_int, help="Start address of the disassembly."
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

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
            # so until pwnlibs gets type annotations we just trick the type checker to to prevent a false positive
            if TYPE_CHECKING:
                d = str(dump)
            else:
                d = dump
            print(disasm(d, vma=args.address))  # type: ignore
            return True


class CmdWriteMem(Cmd):
    keywords = ["writemem"]
    description = "Writes data to a specified memory address."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="Interpret data as hex string (e.g. ff000a20...)",
    )
    parser.add_argument(
        "--int",
        action="store_true",
        help="Interpret data as 32 bit integer (e.g. 0x123)",
    )
    parser.add_argument("--file", "-f", help="Read data from this file instead.")
    parser.add_argument(
        "--repeat",
        "-r",
        default=1,
        type=auto_int,
        help="Number of times to repeat the data (default: %(default)s)",
    )
    parser.add_argument("address", type=auto_int, help="Destination address")
    parser.add_argument(
        "data",
        nargs="*",
        help="Data as string (or hexstring/integer, see --hex, --int)",
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        if args.file is not None:
            data = read(args.file)
        elif len(args.data) > 0:
            data = " ".join(args.data)
            if args.hex:
                try:
                    data = bytearray.fromhex(data)
                except TypeError as e:
                    log.warn("Hex string cannot be converted to bytestring: " + str(e))
                    return False
            elif args.int:
                data = p32(auto_int(data))
        else:
            self.parser.print_usage()
            print("Either data or --file is required!")
            return False

        data = data * args.repeat

        if not self.isAddressInSections(args.address, len(data), sectiontype="RAM"):
            log.warn(
                "Warning: Address 0x%08x (len=0x%x) is not inside a RAM section."
                % (args.address, len(args.data))
            )

        self.progress_log = log.progress("Writing Memory")
        if self.writeMem(
            args.address, data, self.progress_log, bytes_done=0, bytes_total=len(data)
        ):
            self.progress_log.success(
                "Written %d bytes to 0x%08x." % (len(data), args.address)
            )
            return True
        else:
            self.progress_log.failure("Write failed!")
            return False


class CmdWriteAsm(Cmd):
    keywords = ["writeasm", "asm"]
    description = "Writes assembler instructions to a specified memory address."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--dry",
        "-d",
        action="store_true",
        help="Only pass code to the assembler but don't write to memory",
    )
    parser.add_argument(
        "--file",
        "-f",
        help="Open file in text editor, then read assembly from this file.",
    )
    parser.add_argument("address", type=auto_int, help="Destination address")
    parser.add_argument("code", nargs="*", help="Assembler code as string")

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

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
            self.parser.print_usage()
            print("Either code or --file is required!")
            return False

        try:
            data = asm(code, vma=args.address)
        except PwnlibException:
            return False

        if len(data) > 0:
            log.info(
                "Assembler was successful. Machine code (len = %d bytes) is:"
                % len(data)
            )
            log.hexdump(data, begin=args.address)
        else:
            log.info("Assembler didn't produce any machine code.")
            return False

        if args.dry:
            log.info("This was a dry run. No data written to memory!")
            return True

        if not self.isAddressInSections(args.address, len(data), sectiontype="RAM"):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?"
                % (args.address, len(data))
            )
            if not answer:
                return False

        self.progress_log = log.progress("Writing Memory")
        if self.writeMem(
            args.address, data, self.progress_log, bytes_done=0, bytes_total=len(data)
        ):
            self.progress_log.success(
                "Written %d bytes to 0x%08x." % (len(data), args.address)
            )
            return True
        else:
            self.progress_log.failure("Write failed!")
            return False


class CmdExec(Cmd):
    keywords = ["exec", "execute"]
    description = "Writes assembler instructions to RAM and jumps there."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--dry",
        "-d",
        action="store_true",
        help="Only pass code to the assembler but don't write to memory and don't execute",
    )
    parser.add_argument(
        "--edit", "-e", action="store_true", help="Edit command before execution"
    )
    parser.add_argument(
        "--addr",
        "-a",
        type=auto_int,
        default=0x211800,
        help="Destination address of the command instructions",
    )
    parser.add_argument(
        "cmd", help="Name of the command to execute (corresponds to file exec_<cmd>.s)"
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

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
            log.info("Assembler didn't produce any machine code.")
            return False

        if args.edit:
            log.info(
                "Assembler was successful. Machine code (len = %d bytes) is:"
                % len(data)
            )
            log.hexdump(data, begin=args.addr)

        if args.dry:
            log.info("This was a dry run. No data written to memory!")
            return True

        if not self.isAddressInSections(args.addr, len(data), sectiontype="RAM"):
            answer = yesno(
                "Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?"
                % (args.addr, len(args.data))
            )
            if not answer:
                return False

        self.progress_log = log.progress("Writing Memory")
        if not self.writeMem(
            args.addr, data, self.progress_log, bytes_done=0, bytes_total=len(data)
        ):
            self.progress_log.failure("Write failed!")
            return False

        self.progress_log.success(
            "Written %d bytes to 0x%08x." % (len(data), args.addr)
        )

        self.progress_log = log.progress("Launching Command")
        if self.launchRam(args.addr):
            self.progress_log.success("launch_ram cmd was sent successfully!")
            return True
        else:
            self.progress_log.failure("Sending launch_ram command failed!")
            return False


class CmdSendHciCmd(Cmd):
    keywords = ["sendhcicmd"]
    description = "Send an arbitrary HCI command to the BT controller."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "cmdcode", type=auto_int, help="The command code (e.g. 0xfc4c for WriteRam)."
    )
    parser.add_argument(
        "data",
        nargs="*",
        help="Payload as combinations of hexstrings and hex-uint32 (starting with 0x..)",
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        if args.cmdcode > 0xFFFF:
            log.info("cmdcode needs to be in the range of 0x0000 - 0xffff")
            return False

        data = b""
        for data_part in args.data:
            if data_part[0:2] == "0x":
                data += p32(auto_int(data_part))
            else:
                data += bytearray.fromhex(data_part)

        return self.internalblue.sendHciCommand(args.cmdcode, data)


class CmdPatch(Cmd):
    keywords = ["patch"]
    description = "Patches 4 byte of data at a specified ROM address."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="Interpret data as hex string (e.g. ff000a20...)",
    )
    parser.add_argument(
        "--int",
        action="store_true",
        help="Interpret data as 32 bit integer (e.g. 0x123)",
    )
    parser.add_argument(
        "--asm", action="store_true", help="Interpret data as assembler instruction"
    )
    parser.add_argument(
        "--delete", "-d", action="store_true", help="Delete the specified patch."
    )
    parser.add_argument(
        "--slot", "-s", type=auto_int, help="Patchram slot to use (0-128)"
    )
    parser.add_argument("--address", "-a", type=auto_int, help="Destination address")
    parser.add_argument(
        "data",
        nargs="*",
        help="Data as string (or hexstring/integer/instruction, see --hex, --int, --asm)",
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        if args.slot is not None:
            if (
                args.slot < 0
                or args.slot > self.internalblue.fw.PATCHRAM_NUMBER_OF_SLOTS
            ):
                log.warn(
                    "Slot has to be in the range 0 to %i!"
                    % self.internalblue.fw.PATCHRAM_NUMBER_OF_SLOTS
                )
                return False

        # Patch Deletion
        if args.delete:
            if args.slot is not None:
                log.info("Deleting patch in slot %d..." % args.slot)
            elif args.address is not None:
                log.info("Deleting patch at address 0x%x..." % args.address)
            else:
                log.warn("Address or Slot number required!")
                return False
            return self.internalblue.disableRomPatch(args.address, args.slot)

        if args.address is None:
            log.warn("Address is required!")
            return False

        if len(args.data) > 0:
            argument_data = " ".join(args.data)
            if args.hex:
                try:
                    data = binascii.unhexlify(argument_data)
                except TypeError as e:
                    log.warn("Data string cannot be converted to hexstring: " + str(e))
                    return False
            elif args.int:
                data = p32(auto_int(argument_data))
            elif args.asm:
                data = asm(argument_data, vma=args.address)
            else:
                log.warning("--hex, --int or --asm are required")
                return
        else:
            self.parser.print_usage()
            print("Data is required!")
            return False

        if len(data) > 4:
            log.warn("Data size is %d bytes. Trunkating to 4 byte!" % len(data))
            data = data[0:4]
        if len(data) < 4:
            log.warn("Data size is %d bytes. 0-Padding to 4 byte!" % len(data))
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


class CmdSendLmp(Cmd):
    keywords = ["sendlmp"]
    description = "Send LMP packet to another device."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--conn_handle",
        "-c",
        type=auto_int,
        help="Handle of the connection associated with the other device, default is trying to read connection handle (if supported) or setting it to 0x0C.",
    )
    parser.add_argument(
        "--extended",
        "-e",
        action="store_true",
        help="Use extended opcodes (prepend opcode with 0x7F)",
    )
    parser.add_argument(
        "--slave",
        action="store_true",
        help="Send as slave (default is master if auto detection fails)",
    )
    parser.add_argument(
        "--master", action="store_true", help="Send as master (override auto detection)"
    )
    parser.add_argument("opcode", type=auto_int, help="Number of the LMP opcode")
    parser.add_argument("--data", "-d", default="", help="Payload as hexstring.")

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

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
            log.warn("Data string cannot be converted to hexstring: " + str(e))
            return False

        log.info(
            "Sending op=%d data=%s to connection handle=0x%04x"
            % (args.opcode, data.encode("hex"), args.conn_handle)
        )
        return self.internalblue.sendLmpPacket(
            args.opcode, data, is_master, args.conn_handle, extended_op=args.extended
        )


class CmdFuzzLmp(Cmd):
    keywords = ["fuzzlmp"]
    description = "Installs a hook to sendlmp that skips checking opcodes and lengths inside firmware. A remaining firmware constraint is the buffer allocated by lm_allocLmpBlock (32 bytes)."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )

    def work(self):
        return self.internalblue.fuzzLmp()


class CmdSendLcp(Cmd):
    keywords = ["sendlcp"]
    description = "Send LCP packet to another device."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--conn_index",
        "-c",
        type=auto_int,
        help="Connection index, starts at 0 for first connection.",
    )
    parser.add_argument("data", help="Payload as hexstring.")

    def work(self):
        args = self.getArgs()
        if not args:
            return True

        # if not set, just use 0
        if not args.conn_index:
            args.conn_index = 0

        try:
            data = args.data.decode("hex")
        except TypeError as e:
            log.warn("Data string cannot be converted to hexstring: " + str(e))
            return False

        log.info(
            "Sending data=%s to connection index=0x%04x"
            % (data.encode("hex"), args.conn_index)
        )
        return self.internalblue.sendLcpPacket(
            cast("ConnectionIndex", args.conn_index), data
        )


class CmdInfo(Cmd):
    keywords = ["info", "show", "i"]
    description = "Display various types of information parsed from live RAM"
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "type",
        help="""Type of information:
    device:       General information (BT Name/Address, ADB Serial ID).
    connections:  List of valid entries in the connection structure.
    patchram:     List of patches in the patchram table.
    heap / bloc:  List of BLOC structures (Heap Pools).
                  Optional argument: BLOC index or address for more details.
                  Optional argument: verbose Show verbose information
    queue:        List of QUEU structures (Blocking Queues).
    """,
    )

    parser.add_argument("args", nargs="*", help="Optional arguments for each type.")

    def infoConnections(self, args):
        if not hasattr(self.internalblue.fw, "CONNECTION_MAX"):
            log.warn("CONNECTION_MAX not defined in fw.")
            return False

        for i in range(self.internalblue.fw.CONNECTION_MAX):
            connection = self.internalblue.readConnectionInformation(
                cast("ConnectionNumber", i + 1)
            )
            if connection is None:
                continue

            log.info("### | Connection ---%02d--- ###" % i)
            log.info("    - Number:            %d" % connection.connection_number)
            log.info(
                "    - Remote BT address: %s"
                % bt_addr_to_str(connection.remote_address)
            )
            log.info("    - Remote BT name:    %08X" % connection.remote_name_address)
            log.info(
                "    - Master of Conn.:   %s" % str(connection.master_of_connection)
            )
            log.info("    - Conn. Handle:      0x%X" % connection.connection_handle)
            log.info(
                "    - Public RAND:       %s" % bytes_to_hex(connection.public_rand)
            )
            # log.info("    - PIN:               %s"     % bytes_to_hex(connection.pin)
            # log.info("    - BT addr for key:   %s"     % bt_addr_to_str(connection.bt_addr_for_key))
            log.info(
                "    - Effective Key Len: %d byte (%d bit)"
                % (connection.effective_key_len, 8 * connection["effective_key_len"])
            )
            log.info("    - Link Key:          %s" % bytes_to_hex(connection.link_key))
            log.info(
                "    - LMP Features:      %s"
                % bytes_to_hex(connection.extended_lmp_feat)
            )
            log.info(
                "    - Host Supported F:  %s"
                % bytes_to_hex(connection.host_supported_feat)
            )
            log.info("    - TX Power (dBm):    %d" % connection.tx_pwr_lvl_dBm)
            log.info("    - Array Index:       %s" % bytes_to_hex(connection.id))
        print()
        return True

    def infoDevice(self, args):
        for const in ["BD_ADDR", "DEVICE_NAME"]:
            if const not in dir(self.internalblue.fw):
                log.warn(" '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False
        bt_addr = self.readMem(self.internalblue.fw.BD_ADDR, 6)[::-1]
        bt_addr_str = bt_addr_to_str(bt_addr)
        device_name = self.readMem(self.internalblue.fw.DEVICE_NAME, 258)
        device_name_len = device_name[0] - 1
        device_name = device_name[2 : 2 + device_name_len]
        adb_serial = context.device

        log.info("### | Device ###")
        log.info("    - Name:       %s" % device_name.decode("utf-8"))
        log.info("    - ADB Serial: %s" % adb_serial)
        log.info("    - Address:    %s" % bt_addr_str)
        return True

    def infoPatchram(self, args):
        if not hasattr(self.internalblue.fw, "PATCHRAM_NUMBER_OF_SLOTS"):
            log.warn("PATCHRAM_NUMBER_OF_SLOTS not defined in fw.")
            return False

        # try:
        (
            table_addresses,
            table_values,
            table_slots,
        ) = self.internalblue.getPatchramState()
        # except:
        #    log.info("Invalid Patchram Table")
        #    return False

        log.info("### | Patchram Table ###")
        for i in range(self.internalblue.fw.PATCHRAM_NUMBER_OF_SLOTS):
            if table_slots[i] == 1:
                code = disasm(
                    table_values[i], vma=table_addresses[i], byte=False, offset=False
                )
                code = code.replace("    ", " ").replace("\n", ";  ")
                log.info(
                    "[%03d] 0x%08X: %s (%s)"
                    % (i, table_addresses[i], bytes_to_hex(table_values[i]), code)
                )
        return True

    def infoHeap(self, args):
        bloc_for_details = None
        bloc_address = None
        bloc_index = None
        verbose = False
        for arg in args:
            try:
                if arg in ["verbose"]:
                    verbose = True
                elif args[0].startswith("0x"):
                    bloc_address = int(args[0], 16)
                else:
                    bloc_index = int(args[0])
            except TypeError:
                log.warn(
                    "Optional argument is neither a number (decimal) nor an address (hex) nor -v"
                )
                return False

        progress_log = log.progress("Traversing Heap")
        heaplist = self.internalblue.readHeapInformation()  # List of BLOC structs

        if heaplist == False:
            log.debug("No heap returned!")
            progress_log.failure("empty")
            return False

        # Print Bloc Buffer Table
        log.info("  [ Idx ] @Pool-Addr  Buf-Size  Avail/Capacity  Mem-Size @ Addr")
        log.info("  -----------------------------------------------------------------")
        for heappool in heaplist:
            # TODO: waitlist

            marker_str = "> "
            if bloc_address is not None and heappool["address"] == bloc_address:
                bloc_for_details = heappool
            elif bloc_index is not None and heappool["index"] == bloc_index:
                bloc_for_details = heappool
            else:
                marker_str = "  "

            log.info(
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
                    log.warn(
                        "            Corruption warning might be wrong for allocated buffers!"
                    )

                log.info("            Buffer   : Header    Status")
                log.info("            -------------------------------")
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

                    log.info(info)
                log.info("")

        # Print Bloc Buffer Details
        if bloc_for_details is None:
            progress_log.success("done")
            return True

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
                log.info(
                    "dumping buffer 0x%06X from BLOC[%d]:"
                    % (buffer_address + 4, bloc_for_details["index"])
                )
                log.hexdump(buf[4:], begin=buffer_address + 4)

        progress_log.success("done")
        return True

    def infoQueue(self, args):
        progress_log = log.progress("Traversing Queues")
        queuelist = self.internalblue.readQueueInformation()  # List of QUEU structs

        if queuelist is None:
            log.debug("No queues returned!")
            progress_log.failure("empty")
            return False

        log.info(
            "[ Idx  ] @Queue-Addr  Queue-Name          Items/Free/Capacity  Item-Size  Buffer"
        )
        log.info(
            "--------------------------------------------------------------------------------"
        )
        for queue in [vars(element) for element in queuelist]:
            # TODO: waitlist
            log.info(
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
        #            log.info("QUEUE[{index}] @ 0x{address:06X}:  {name:10s}  ({available_items:d} items)\n"
        #                     "---------------------------------------------------------------------------")
        #            for item in queue["items"]:
        #                log.hexdump(item, begin=0x0)

        progress_log.success("done")
        return True

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        subcommands = {
            "connections": self.infoConnections,
            "device": self.infoDevice,
            "patchram": self.infoPatchram,
            "heap": self.infoHeap,
            "bloc": self.infoHeap,
            "queue": self.infoQueue,
        }

        if args.type in subcommands:
            return subcommands[args.type](args.args)
        else:
            log.warn(
                "Unkown type: %s\nKnown types: %s"
                % (args.type, list(subcommands.keys()))
            )
            return False


class CmdTracepoint(Cmd):
    keywords = ["trace", "tracepoint", "tp"]
    description = "Manage tracepoints."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument("command", help="One of: add/set, remove/delete/del, list/show")
    parser.add_argument(
        "address", type=auto_int, nargs="?", help="Address of the tracepoint"
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        if args.command in ["add", "set"]:
            if args.address is None:
                log.warn("Missing address. Use tracepoint add <address>")
                return False
            log.info("Inserting tracepoint at 0x%x..." % args.address)
            if self.internalblue.addTracepoint(args.address):
                log.info("Tracing instruction at address 0x%x." % args.address)
            else:
                return False

        elif args.command in ["remove", "delete", "del"]:
            if args.address is None:
                log.warn("Missing address. Use tracepoint del <address>")
                return False
            log.info("Deleting tracepoint at 0x%x..." % args.address)
            if not self.internalblue.deleteTracepoint(args.address):
                return False
            log.info("Deleted tracepoint at address 0x%x" % args.address)

        elif args.command in ["list", "show"]:
            if len(self.internalblue.tracepoints) == 0:
                log.info("No active tracepoints.")
            else:
                tracepoints = "\n".join(
                    ["  - 0x%x" % tp[0] for tp in self.internalblue.tracepoints]
                )
                log.info("Active Tracepoints:\n" + tracepoints)

        return True


class CmdBreakpoint(Cmd):
    keywords = ["break", "breakpoint", "bp"]
    description = "Add breakpoint. This will crash, but produces a stackdump at the given address."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "address", type=auto_int, nargs="?", help="Address of the breakpoint"
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        log.info("Inserting breakpoint at 0x%x..." % args.address)
        self.internalblue.patchRom(args.address, b'\x00\xbe\x00\x00')  # on ARM, hex code for a break point is 0xBE00

        return True


class CmdConnectCmd(Cmd):
    keywords = ["connect", "c"]
    description = "Initiate a connection to a remote Bluetooth device"
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "btaddr", help="Bluetooth address of the remote device (with or without ':'."
    )

    def work(self):
        args = self.getArgs()
        if not args:
            return True

        addr = parse_bt_addr(args.btaddr)
        if not addr:
            return False

        self.internalblue.connectToRemoteDevice(addr)

        return True


class CmdConnectLeCmd(Cmd):
    keywords = ["connectle", "leconnect", "cle", "lec"]
    description = "Initiate a connection to a remote LE Bluetooth device"
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--addrtype",
        type=auto_int,
        default=0,
        help="Address type: Public Device (0, default), Random Device (1), Public Identity (2), Random static Identity (3)",
    )
    parser.add_argument(
        "btaddr", help="Bluetooth address of the remote device (with or without ':'."
    )

    def work(self):
        args = self.getArgs()
        if args is None:
            return True

        addr = parse_bt_addr(args.btaddr)
        if not addr:
            return False

        self.internalblue.connectToRemoteLEDevice(addr, args.addrtype)

        return True


class CmdCustom(Cmd):
    keywords = ["custom", "c"]
    description = "Add custom command to internalblue"

    actions = ["list", "add", "run", "remove"]

    for keyword in list(keywords):
        for action in actions:
            keywords.append("%s %s" % (keyword, action))

    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )

    parser.add_argument("do", help="one of (%s)" % ", ".join(actions))
    parser.add_argument("alias", nargs="?", default=None, help="alias of the cmd")
    parser.add_argument("cmd", nargs="*", default=[], help="only used with add")

    file = "custom.json"
    custom_commands = {}

    if os.path.isfile(file):
        try:
            with open(file, "r") as reader:
                custom_commands = json.loads(reader.read())
        except Exception as e:
            log.critical(
                "Encountered an error while trying to load custom commands!" f"{e}"
            )

    @staticmethod
    def save(custom_commands):
        with open(CmdCustom.file, "w") as writer:
            json.dump(custom_commands, writer, sort_keys=True, indent=2)

    def work(self):
        args = self.getArgs()

        if args is None:
            return True

        if args.do == "list":
            custom_cmds = [
                "\t%s\t\t%s\n" % (k, v)
                for k, v in sorted(CmdCustom.custom_commands.items())
            ]
            log.info("Custom commands:\n%s" % "".join(custom_cmds))
            return True

        if args.do == "add":

            alias = args.alias
            cmd = " ".join(args.cmd)

            log.debug("Alias: " + alias)
            log.debug("Command " + cmd)

            # if cmd not found, return False
            if not findCmd(cmd.split(" ")[0]):
                log.warning("Custom command not found: " + cmd.split(" ")[0])
                return False

            CmdCustom.custom_commands[alias] = cmd
            CmdCustom.save(CmdCustom.custom_commands)

            log.info("Custom Command added: " + alias)

        if args.do == "run":
            alias = args.alias

            # check if no cmd has been passed
            if len(args.cmd) == 0:

                if alias in CmdCustom.custom_commands:

                    cmd = CmdCustom.custom_commands[alias]

                    matching_cmd = findCmd(cmd.split(" ")[0])

                    if matching_cmd is None:
                        log.warn("Command unknown: " + cmd)
                        return False

                    cmd_instance = matching_cmd(cmd, self.internalblue)

                    if not cmd_instance.work():
                        log.warn("Command failed: " + str(cmd_instance))

                    return True

                log.info("Custom Command not found: " + alias)

                return False

            return True

        if args.do == "remove":
            if args.alias not in CmdCustom.custom_commands:
                log.info("Custom command not found: " + args.alias)
                return False

            CmdCustom.custom_commands.pop(args.alias, None)

            log.info("Custom command removed: " + args.alias)

            return True

        return True


class CmdReadAfhChannelMap(Cmd):
    keywords = ["readafh"]
    description = "Read adaptive freuency hopping (AFH) channel map."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--conn_handle",
        "-c",
        type=auto_int,
        help="Handle of the connection associated with the other device, default is trying to read all connection handles (if supported) or setting it to 0x0C.",
    )

    def work(self):
        args = self.getArgs()

        if args is None or args.conn_handle is None:
            # automatically get all connection handles if not set
            if hasattr(self.internalblue.fw, "CONNECTION_MAX"):
                for i in range(self.internalblue.fw.CONNECTION_MAX):
                    connection = self.internalblue.readConnectionInformation(
                        cast("ConnectionNumber", i + 1)
                    )
                    if connection is None:
                        continue
                    else:
                        self.readafh(connection.connection_handle)
                return True
            # if not set but connection struct unknown, typical connection handles seem to be 0x0b...0x0d
            else:
                return self.readafh(0x0C)

        return self.readafh(args.conn_handle)

    def readafh(self, handle):
        """ This is a standard HCI command but might be useful when playing around with the physical layer.
        """
        response = self.internalblue.sendHciCommand(
            HCI_COMND.Read_AFH_Channel_Map, p16(handle)
        )

        if len(response) < 17 or response[8:] == b"\x00" * 9:
            log.info("Connection 0x%04x is not established." % handle)
            return False

        log.info("Connection Handle: 0x%04x" % handle)
        log.info("AFH Enabled: %s" % bool(response[7] != 0))
        channels = ""
        for c in response[8:]:
            bits = format(c, "08b")
            for b in bits:
                if b == "1":
                    channels = channels + " *"
                else:
                    channels = channels + "  "

        log.info(
            "AFH Channel Map:\n"
            "     0 1 2 3 4 5 6 7 8 9\n"
            "00: " + channels[0:20] + "\n"
            "10: " + channels[20:40] + "\n"
            "20: " + channels[40:60] + "\n"
            "30: " + channels[60:80] + "\n"
            "40: " + channels[80:100] + "\n"
            "50: " + channels[100:120] + "\n"
            "60: " + channels[120:140] + "\n"
            "70: " + channels[140:158] + "\n"
        )

        return True


class CmdSendDiagCmd(Cmd):
    keywords = ["diag", "sendh4"]
    description = (
        "Send an arbitrary Broadcom H4 diagnostic command to the BT controller."
    )
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument(
        "--type",
        type=auto_int,
        default=0x07,
        help="Type. Default is 0x07, but you can use 0x02 for ACL and 0x03 for SCO."
        "Other values might crash.",
    )
    parser.add_argument(
        "data",
        nargs="*",
        help="Payload as combinations of hexstrings and hex-uint32 (starting with 0x..). "
        "Known commands so far: Reset ACL BR Stats (b9), Get ACL BR Stats (c1), "
        "Get ACL EDR Stats (c2), Get AUX Stats (c3), Get Connections (cf), "
        "Enable Link Manager Diagnostics (f001), Get Memory Peek (f1), Get Memory Poke (f2), "
        "Get Memory Dump (f3), Packet Test (f6).",
    )

    def work(self):

        args = self.getArgs()
        if not args or not args.data:
            return True

        data = b""
        for data_part in args.data:
            if data_part[0:2] == "0x":
                data += p32(auto_int(data_part))
            else:
                data += binascii.unhexlify(data_part)

        self.internalblue.sendH4(args.type, data)

        return True


class CmdLaunch(Cmd):
    keywords = ["launch"]
    description = "Executes launch RAM HCI command. Note that this causes threading issues on some chips."
    parser = argparse.ArgumentParser(
        prog=keywords[0],
        description=description,
        epilog="Aliases: " + ", ".join(keywords),
    )
    parser.add_argument("address", type=auto_int, help="Execute this address.")

    def work(self):
        args = self.getArgs()
        if not args:
            return False

        self.internalblue.launchRam(args.address)
        return True
