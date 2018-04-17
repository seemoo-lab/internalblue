#!/usr/bin/python2

# cmds.py
#
# This is a submodule of brcm_bt_debugtool.py
# It contains all implemented commands. New commands can be added by defining
# a new subclass of Cmd. The new subclass must have the attributes 'keywords'
# and 'description' and should overwrite the method 'work' in order to accomplish
# the desired behavior.
#
# Copyright (c) 2017 Dennis Mantz. (MIT License)
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
import os
import sys
import Queue
import inspect
import argparse
import subprocess
import textwrap

import global_state
import hci

def auto_int(x):
    return int(x, 0)

class Cmd:
    keywords = []

    #            start,    end,      is_rom?
    sections = [(0x0,      0x90000,  True),
                (0xd0000,  0xd8000,  False),
               #(0xe0000,  0x1f0000, True),
                (0x200000, 0x228000, False),
                (0x260000, 0x268000, True),
               #(0x280000, 0x2a0000, True),
                (0x318000, 0x320000, True),
                (0x324000, 0x360000, False),
                (0x362000, 0x362100, False),
                (0x363000, 0x363100, False),
                (0x600000, 0x600800, True),
                (0x640000, 0x640800, True),
                (0x650000, 0x650800, True),
               #(0x680000, 0x800000, True)
               ]

    memory_image = None
    memory_image_template_filename = "_memdump_template.bin"

    def __init__(self, cmdline, recvQueue, hci_tx):
        self.cmdline = cmdline
        self.recvQueue = recvQueue
        self.hci_tx = hci_tx

    def __str__(self):
        return self.cmdline

    def work(self):
        return True

    def abort_cmd(self):
        self.aborted = True
        global_state.cmd_running = False
        if hasattr(self, 'progress_log'):
            self.progress_log.failure("Command aborted")

    def getArgs(self):
        try:
            return self.parser.parse_args(self.cmdline.split(' ')[1:])
        except SystemExit:
            return None

    def isAddressInSections(self, address, length=0, sectiontype=""):
        for sectionstart, sectionend, is_rom in self.sections:
            if (sectiontype.upper() == "ROM" and not is_rom) or (sectiontype.upper() == "RAM" and is_rom):
                continue

            if(address >= sectionstart and address <= sectionend):
                if(address + length <= sectionend):
                    return True
                else:
                    return False
        return False

    def readMem(self, start, end, progress_log=None, bytes_done=0, bytes_total=0):
        read_addr = start
        byte_counter = 0
        outbuffer = ''
        memory_type = None
        while(read_addr < end):
            # Send hci frame
            bytes_left = (end-start) - byte_counter
            blocksize = bytes_left
            if blocksize > 251:
                blocksize = 251

            self.hci_tx.sendReadRamCmd(read_addr, blocksize)

            while(True):
                # Receive response
                try:
                    hcipkt, orig_len, inc_len, flags, drops, recvtime = self.recvQueue.get(timeout=0.5)
                except Queue.Empty:
                    if global_state.exit_requested or (hasattr(self, 'aborted') and self.aborted):
                        return None
                    continue

                if isinstance(hcipkt, hci.HCI_Event):
                    if(hcipkt.event_code == 0x0e): # Cmd Complete event
                        if(hcipkt.data[0:3] == '\x01\x4d\xfc'):
                            memory_type = data = ord(hcipkt.data[3])
                            if memory_type != 0:
                                log.warning("readMem: [TODO] Got memory type != 0 : 0x%02X" % memory_type)
                            data = hcipkt.data[4:]
                            outbuffer += data
                            read_addr += len(data)
                            byte_counter += len(data)
                            if(progress_log != None):
                                if(bytes_total > 0):
                                    msg = "receiving data... %d / %d Bytes" % (bytes_done+byte_counter, bytes_total)
                                else:
                                    msg = "receiving data... 0x%08x" % start
                                progress_log.status(msg)
                            break
        return outbuffer  # TODO: return memory_type

    def writeMem(self, address, data, progress_log=None, bytes_done=0, bytes_total=0):
        write_addr = address
        byte_counter = 0
        while(byte_counter < len(data)):
            # Send hci frame
            bytes_left = len(data) - byte_counter
            blocksize = bytes_left
            if blocksize > 251:
                blocksize = 251

            self.hci_tx.sendWriteRamCmd(write_addr, data[byte_counter:byte_counter+blocksize])

            while(True):
                # Receive response
                try:
                    hcipkt, orig_len, inc_len, flags, drops, recvtime = self.recvQueue.get(timeout=0.5)
                except Queue.Empty:
                    if global_state.exit_requested or (hasattr(self, 'aborted') and self.aborted):
                        return False
                    continue

                if isinstance(hcipkt, hci.HCI_Event):
                    if(hcipkt.event_code == 0x0e): # Cmd Complete event
                        if(hcipkt.data[0:3] == '\x01\x4c\xfc'):
                            if(hcipkt.data[3] != '\x00'):
                                log.warn("Got error code %x in command complete event." % hcipkt.data[3])
                                return False
                            write_addr += blocksize
                            byte_counter += blocksize
                            if(progress_log != None):
                                if(bytes_total > 0):
                                    msg = "sending data... %d / %d Bytes" % (bytes_done+byte_counter, bytes_total)
                                else:
                                    msg = "sending data... 0x%08x" % start
                                progress_log.status(msg)
                            break
        return True


    def initMemoryImage(self):
        bytes_done = 0
        if(not os.path.exists(self.memory_image_template_filename)):
            log.info("No template found. Need to read ROM sections as well!")
            bytes_total = sum([end-start for start,end,is_rom in self.sections])
            self.progress_log = log.progress("Initialize internal memory image")
            dumped_sections = {}
            for sectionstart, sectionend, is_rom in self.sections:
                dumped_sections[sectionstart] = self.readMem(sectionstart, sectionend, self.progress_log, bytes_done, bytes_total)
                bytes_done += sectionend-sectionstart
            self.progress_log.success("Received Data: complete")
            Cmd.memory_image = fit(dumped_sections, filler='\x00')
            f = open(self.memory_image_template_filename, 'wb')
            f.write(Cmd.memory_image)
            f.close()
        else:
            log.info("Template found. Only read non-ROM sections!")
            Cmd.memory_image = read(self.memory_image_template_filename)
            self.refreshMemoryImage()

    def refreshMemoryImage(self):
        bytes_done = 0
        bytes_total = sum([end-start for start,end,is_rom in self.sections if not is_rom])
        self.progress_log = log.progress("Refresh internal memory image")
        for sectionstart, sectionend, is_rom in self.sections:
            if not is_rom:
                sectiondump = self.readMem(sectionstart, sectionend, self.progress_log, bytes_done, bytes_total)
                Cmd.memory_image = Cmd.memory_image[0:sectionstart] + sectiondump + Cmd.memory_image[sectionend:]
                bytes_done += sectionend-sectionstart
        self.progress_log.success("Received Data: complete")

    def getMemoryImage(self, refresh=False):
        if Cmd.memory_image == None:
            self.initMemoryImage()
        elif refresh:
            self.refreshMemoryImage()
        return Cmd.memory_image

    def launchRam(self, address):
        self.hci_tx.sendLaunchRamCmd(address)

        while(True):
            # Receive response
            try:
                hcipkt, orig_len, inc_len, flags, drops, recvtime = self.recvQueue.get(timeout=0.5)
            except Queue.Empty:
                if global_state.exit_requested or (hasattr(self, 'aborted') and self.aborted):
                    return False
                continue

            if isinstance(hcipkt, hci.HCI_Event):
                if(hcipkt.event_code == 0x0e): # Cmd Complete event
                    if(hcipkt.data[0:3] == '\x01\x4e\xfc'):
                        if(hcipkt.data[3] != '\x00'):
                            log.warn("Got error code %x in command complete event." % hcipkt.data[3])
                            return False
                        break
        return True




#
# Start of implemented commands:
#

class CmdHelp(Cmd):
    keywords = ['help', '?']
    description = "Display available commands. Use help <cmd> to display command specific help."

    def work(self):
        args = self.cmdline.split(' ')
        command_list = [obj for name, obj in inspect.getmembers(sys.modules[__name__]) 
                            if inspect.isclass(obj) and issubclass(obj, Cmd)][1:]
        if(len(args) > 1):
            cmd = [c for c in command_list if args[1] in c.keywords]
            if(len(cmd) < 1):
                log.info("No command with the name: " + args[1])
                return True
            if hasattr(cmd[0],'parser'):
                cmd[0].parser.print_help()
            else:
                print(cmd[0].description)
                print("Aliases: " + " ".join(cmd[0].keywords))
        else:
            for cmd in command_list:
                print(cmd.keywords[0].ljust(15) + 
                        ("\n" + " "*15).join(textwrap.wrap(cmd.description, 60)))
        return True

class CmdExit(Cmd):
    keywords = ['exit', 'quit', 'q', 'bye']
    description = "Exit the program."

    def work(self):
        global_state.exit_requested = True
        return True

class CmdLogLevel(Cmd):
    keywords = ['log_level', 'loglevel', 'verbosity']
    description = "Change the verbosity of log messages."
    log_levels = ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("level",
                        help="New log level (%s)" % ", ".join(log_levels))

    def work(self):
        args = self.getArgs()
        if args==None:
            return True
        loglevel = args.level
        if(loglevel.upper() in self.log_levels):
            context.log_level = loglevel
            global_state.log_level = loglevel
            log.info("New log level: " + str(context.log_level))
            return True
        else:
            log.warn("Not a valid log level: " + loglevel)
            return False

class CmdListen(Cmd):
    keywords = ['listen']
    description = "Dump every received HCI packet on the screen."

    def work(self):
        self.progress_log = log.progress("Listening... (stop with Ctrl-C)")
        self.saved_loglevel = global_state.log_level
        global_state.log_level = 'debug'
        while True:
            time.sleep(1)

    def abort_cmd(self):
        Cmd.abort_cmd(self)
        global_state.log_level = self.saved_loglevel

class CmdDumpMem(Cmd):
    keywords = ['dumpmem', 'memdump']
    description = "Dumps complete memory image into a file."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--norefresh", "-n", action="store_true",
                        help="Do not refresh internal memory image before dumping to file.")
    parser.add_argument("--file", "-f", default="memdump.bin",
                        help="Filename of memory dump (default: %(default)s)")

    def work(self):
        args = self.getArgs()
        if args==None:
            return True

        if(os.path.exists(args.file)):
            if not yesno("Overwrite '%s'?" % os.path.abspath(args.file)):
                return False
        
        dump = self.getMemoryImage(refresh=not args.norefresh)
        f = open(args.file, 'wb')
        f.write(dump)
        f.close()
        log.info("Memory dump saved in '%s'!" % os.path.abspath(args.file))
        return True

class CmdSearchMem(Cmd):
    keywords = ['searchmem', 'memsearch']
    description = "Search a pattern (string or hex) in the memory image."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--refresh", "-r", action="store_true",
                        help="Refresh internal memory image before searching.")
    parser.add_argument("--hex", action="store_true",
                        help="Interpret pattern as hex string (e.g. ff000a20...)")
    parser.add_argument("--address", "-a", action="store_true",
                        help="Interpret pattern as address (hex)")
    parser.add_argument("--context", "-c", type=auto_int, default=0,
                        help="Length of the hexdump before and after the matching pattern (default: %(default)s).")
    parser.add_argument("pattern", nargs='*',
                        help="Search Pattern")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        pattern = ' '.join(args.pattern)
        highlight = pattern
        if args.hex:
            try:
                pattern = pattern.decode('hex')
                highlight = pattern
            except TypeError as e:
                log.warn("Search pattern cannot be converted to hexstring: " + str(e))
                return False
        elif args.address:
            pattern = p32(int(pattern, 16))
            highlight = [x for x in pattern if x != '\x00']

        memimage = self.getMemoryImage(refresh=args.refresh)
        matches = [m.start(0) for m in re.finditer(re.escape(pattern), memimage)]

        hexdumplen = (len(pattern) + 16) & 0xFFFF0
        for match in matches:
            startadr = (match & 0xFFFFFFF0) - args.context
            endadr = (match+len(pattern)+16 & 0xFFFFFFF0) + args.context
            log.info("Match at 0x%08x:" % match)
            log.hexdump(memimage[startadr:endadr], begin=startadr, highlight=highlight)
        return True

class CmdHexdump(Cmd):
    keywords = ['hexdump', 'hd']
    description = "Display a hexdump of a specified region in the memory."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--length", "-l", type=auto_int, default=256,
                        help="Length of the hexdump (default: %(default)s).")
    parser.add_argument("address", type=auto_int,
                        help="Start address of the hexdump.")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        #if not self.isAddressInSections(args.address, args.length):
        #    answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?" % (args.address, args.length))
        #    if not answer:
        #        return False

        dump = self.readMem(args.address, args.address + args.length)

        if dump == None:
            return False

        log.hexdump(dump, begin=args.address)
        return True

class CmdTelescope(Cmd):
    keywords = ['telescope']
    description = "Display a specified region in the memory and follow pointers to valid addresses."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--length", "-l", type=auto_int, default=64,
                        help="Length of the telescope dump (default: %(default)s).")
    parser.add_argument("address", type=auto_int,
                        help="Start address of the telescope dump.")

    def telescope(self, data, depth):
        val = u32(data[0:4])
        if(depth > 0 and self.isAddressInSections(val,0x20)):
            newdata = self.readMem(val, val + 0x20)
            recursive_result = self.telescope(newdata, depth-1)
            recursive_result.insert(0, val)
            return recursive_result
        else:
            s = ''
            for c in data:
                if isprint(c):
                    s += c
                else:
                    break
            return [val, s]

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        if not self.isAddressInSections(args.address, args.length):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?" % (args.address, args.length))
            if not answer:
                return False

        dump = self.readMem(args.address, args.address + args.length + 4)
        if dump == None:
            return False

        for index in range(0, len(dump)-4, 4):
            chain = self.telescope(dump[index:], 4)
            output = "0x%08x: " % (args.address+index)
            output += ' -> '.join(["0x%08x" % x for x in chain[:-1]])
            output += ' \"' + chain[-1] + '"'
            log.info(output)
        return True

class CmdDisasm(Cmd):
    keywords = ['disasm', 'disassemble', 'd']
    description = "Display a disassembly of a specified region in the memory."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--length", "-l", type=auto_int, default=128,
                        help="Length of the disassembly (default: %(default)s).")
    parser.add_argument("address", type=auto_int,
                        help="Start address of the disassembly.")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        if not self.isAddressInSections(args.address, args.length):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?" % (args.address, args.length))
            if not answer:
                return False

        dump = self.readMem(args.address, args.address + args.length)

        if dump == None:
            return False

        print(disasm(dump, vma=args.address))
        return True

class CmdWriteMem(Cmd):
    keywords = ['writemem']
    description = "Writes data to a specified memory address."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--hex", action="store_true",
                        help="Interpret data as hex string (e.g. ff000a20...)")
    parser.add_argument("--int", action="store_true",
                        help="Interpret data as 32 bit integer (e.g. 0x123)")
    parser.add_argument("--file", "-f",
                        help="Read data from this file instead.")
    parser.add_argument("--repeat", "-r", default=1, type=auto_int,
                        help="Number of times to repeat the data (default: %(default)s)")
    parser.add_argument("address", type=auto_int,
                        help="Destination address") 
    parser.add_argument("data", nargs="*",
                        help="Data as string (or hexstring/integer, see --hex, --int)")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        if args.file != None:
            data = read(args.file)
        elif len(args.data) > 0:
            data = ' '.join(args.data)
            if args.hex:
                try:
                    data = data.decode('hex')
                except TypeError as e:
                    log.warn("Data string cannot be converted to hexstring: " + str(e))
                    return False
            elif args.int:
                data = p32(auto_int(data))
        else:
            self.parser.print_usage()
            print("Either data or --file is required!")
            return False

        data = data * args.repeat

        if not self.isAddressInSections(args.address, len(data), sectiontype="RAM"):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?" % (args.address, len(args.data)))
            if not answer:
                return False

        self.progress_log = log.progress("Writing Memory")
        if self.writeMem(args.address, data, self.progress_log, bytes_done=0, bytes_total=len(data)):
            self.progress_log.success("Written %d bytes to 0x%08x." % (len(data), args.address))
            return True
        else:
            self.progress_log.failure("Write failed!")
            return False

class CmdWriteAsm(Cmd):
    keywords = ['writeasm', 'asm']
    description = "Writes assembler instructions to a specified memory address."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--dry", "-d", action="store_true",
                        help="Only pass code to the assembler but don't write to memory")
    parser.add_argument("--file", "-f",
                        help="Open file in text editor, then read assembly from this file.")
    parser.add_argument("address", type=auto_int,
                        help="Destination address") 
    parser.add_argument("code", nargs="*",
                        help="Assembler code as string")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        if args.file != None:
            if(not os.path.exists(args.file)):
                f = open(args.file, "w")
                f.write("/* Write arm thumb code here.\n")
                f.write("   Use '@' or '//' for single line comments or C-like block comments. */\n")
                f.write("\n// 0x%08x:\n\n" % args.address)
                f.close()

            editor = os.environ.get("EDITOR", "vim")
            subprocess.call([editor, args.file])

            code = read(args.file)
        elif len(args.code) > 0:
            code = ' '.join(args.code)
        else:
            self.parser.print_usage()
            print("Either code or --file is required!")
            return False

        try:
            data = asm(code, vma=args.address)
        except PwnlibException:
            return False

        if len(data)>0:
            log.info("Assembler was successful. Machine code (len = %d bytes) is:" % len(data))
            log.hexdump(data, begin=args.address)
        else:
            log.info("Assembler didn't produce any machine code.")
            return False

        if(args.dry):
            log.info("This was a dry run. No data written to memory!")
            return True

        if not self.isAddressInSections(args.address, len(data), sectiontype="RAM"):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?" % (args.address, len(args.data)))
            if not answer:
                return False

        self.progress_log = log.progress("Writing Memory")
        if self.writeMem(args.address, data, self.progress_log, bytes_done=0, bytes_total=len(data)):
            self.progress_log.success("Written %d bytes to 0x%08x." % (len(data), args.address))
            return True
        else:
            self.progress_log.failure("Write failed!")
            return False


class CmdExec(Cmd):
    keywords = ['exec', 'execute']
    description = "Writes assembler instructions to RAM and jumps there."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--dry", "-d", action="store_true",
                        help="Only pass code to the assembler but don't write to memory and don't execute")
    parser.add_argument("--edit", "-e", action="store_true",
                        help="Edit command before execution")
    parser.add_argument("--addr", "-a", type=auto_int, default=0x210000,
                        help="Destination address of the command instructions") 
    parser.add_argument("cmd",
                        help="Name of the command to execute (corresponds to file exec_<cmd>.s)")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        filename = "exec_%s.s" % args.cmd
        if not os.path.exists(filename):
            f = open(filename, "w")
            f.write("/* Write arm thumb code here.\n")
            f.write("   Use '@' or '//' for single line comments or C-like block comments. */\n")
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

        if len(data)==0:
            log.info("Assembler didn't produce any machine code.")
            return False

        if args.edit:
            log.info("Assembler was successful. Machine code (len = %d bytes) is:" % len(data))
            log.hexdump(data, begin=args.addr)

        if(args.dry):
            log.info("This was a dry run. No data written to memory!")
            return True

        if not self.isAddressInSections(args.addr, len(data), sectiontype="RAM"):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a RAM section. Continue?" % (args.addr, len(args.data)))
            if not answer:
                return False

        self.progress_log = log.progress("Writing Memory")
        if not self.writeMem(args.addr, data, self.progress_log, bytes_done=0, bytes_total=len(data)):
            self.progress_log.failure("Write failed!")
            return False

        self.progress_log.success("Written %d bytes to 0x%08x." % (len(data), args.addr))

        self.progress_log = log.progress("Launching Command")
        if self.launchRam(args.addr):
            self.progress_log.success("launch_ram cmd was sent successfully!")
            return True
        else:
            self.progress_log.failure("Sending launch_ram command failed!")
            return False

class CmdSendHciCmd(Cmd):
    keywords = ['sendhcicmd']
    description = "Send an arbitrary hci command to the BT controller"
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("cmdcode", type=auto_int,
                        help="The command code (e.g. 0xfc4c for WriteRam).")
    parser.add_argument("data", nargs="*",
                        help="Payload as combinations of hexstrings and hex-uint32 (starting with 0x..)")

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        if args.cmdcode > 0xffff:
            log.info("cmdcode needs to be in the range of 0x0000 - 0xffff")
            return False

        data = ''
        for data_part in args.data:
            if data_part[0:2] == "0x":
                data += p32(auto_int(data_part))
            else:
                data += data_part.decode('hex')

        self.hci_tx.sendCmd(args.cmdcode, data)

        return True

class CmdPatchRom(Cmd):
    keywords = ['patchrom', 'patch']
    description = "Patches 4 byte of data at a specified ROM address."
    parser = argparse.ArgumentParser(prog=keywords[0],
                                     description=description,
                                     epilog="Aliases: " + ", ".join(keywords))
    parser.add_argument("--hex", action="store_true",
                        help="Interpret data as hex string (e.g. ff000a20...)")
    parser.add_argument("--int", action="store_true",
                        help="Interpret data as 32 bit integer (e.g. 0x123)")
    parser.add_argument("--asm", action="store_true",
                        help="Interpret data as assembler instruction")
    parser.add_argument("slot", type=auto_int,
                        help="Patchram slot to use (0-130)") 
    parser.add_argument("address", type=auto_int,
                        help="Destination address") 
    parser.add_argument("data", nargs="*",
                        help="Data as string (or hexstring/integer, see --hex, --int)")

    # Not so nice hack to keep track of used slots:
    slot_dwords = [0xffffffff, 0xffffffff, 0xffffffff, 0x0000ffff, 0x00000000]

    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        if len(args.data) > 0:
            data = ' '.join(args.data)
            if args.hex:
                try:
                    data = data.decode('hex')
                except TypeError as e:
                    log.warn("Data string cannot be converted to hexstring: " + str(e))
                    return False
            elif args.int:
                data = p32(auto_int(data))
            elif args.asm:
                data = asm(data, vma=args.address)
        else:
            self.parser.print_usage()
            print("Data is required!")
            return False

        if args.slot < 0 or args.slot > 130:
            log.warn("Slot has to be in the range 0 to 130!")
            return False

        if len(data) > 4:
            log.warn("Data size is %d bytes. Trunkating to 4 byte!" % len(data))
            data = data[0:4]
        if len(data) < 4:
            log.warn("Data size is %d bytes. 0-Padding to 4 byte!" % len(data))
            data = data.ljust(4, "\x00")

        if not self.isAddressInSections(args.address, len(data), sectiontype="ROM"):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a ROM section. Continue?" % (args.address, len(data)))
            if not answer:
                return False

        # We need to enable the slot by setting a bit in a multi-dword bitfield
        target_dword = int(args.slot / 32)
        target_bit = args.slot % 32

        if self.slot_dwords[target_dword] & (0b1 << target_bit):
            log.warn("Slot %d is already in use. Overwriting..." % args.slot)

        self.slot_dwords[target_dword] |= 0b1 << target_bit

        # Write new value to patchram value table at 0xd0000
        self.writeMem(0xd0000 + args.slot*4, data)

        # Write address to patchram target table at 0x31000
        self.writeMem(0x310000 + args.slot*4, p32(args.address >> 2))

        # Enable patchram slot (enable bitfield starts at 0x310204)
        self.writeMem(0x310204 + target_dword*4, p32(self.slot_dwords[target_dword]))
        return True





