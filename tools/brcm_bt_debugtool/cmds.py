#!/usr/bin/python2

# Dennis Mantz

from pwn import *
import os
import sys
import Queue
import inspect

import global_state
import hci

def getValueFromCmdline(cmdline):
    """Returns the value for cmdlines like:
       key=value
       key = value
       key value"""

    space_separated = cmdline.split(' ')
    if(len(space_separated) > 1):
        if(len(space_separated) == 2):
            return space_separated[1]
        elif(len(space_separated) == 3 and space_separated[1] == '='):
            return space_separated[2]
        else:
            raise ValueError("Cannot extract value from cmd")
    else:
        equal_separated = cmdline.split('=')
        if(len(equal_separated) == 2):
            return equal_separated[1]
        else:
            raise ValueError("Cannot extract value from cmd")

class Cmd:
    keywords = []

    #            start,    end,      is_rom?
    sections = [(0x0,      0x90000,  True),
                (0xd0000,  0xd8000,  False),
                (0xe0000,  0x1f0000, True),
                (0x200000, 0x228000, False),
                (0x260000, 0x268000, True),
                (0x280000, 0x2a0000, True),
                (0x318000, 0x320000, True),
                (0x324000, 0x360000, False),
                (0x362000, 0x362100, False),
                (0x363000, 0x363100, False),
                (0x600000, 0x600800, True),
                (0x640000, 0x640800, True),
                (0x650000, 0x650800, True),
                (0x680000, 0x800000, True)]

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
        if hasattr(self, 'progress_log'):
            self.progress_log.failure("Command aborted")

    def isAddressInSections(self, address, length=0):
        for sectionstart, sectionend, is_rom in self.sections:
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
                    continue

                if isinstance(hcipkt, hci.HCI_Event):
                    if(hcipkt.event_code == 0x0e): # Cmd Complete event
                        if(hcipkt.data[0:4] == '\x01\x4d\xfc\x00'):
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
        return outbuffer

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
            f.write(Cmd.memory)
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

class CmdHelp(Cmd):
    keywords = ['help', '?']

    def work(self):
        command_list = [obj for name, obj in inspect.getmembers(sys.modules[__name__]) 
                            if inspect.isclass(obj) and issubclass(obj, Cmd)]
        for cmd in command_list:
            print(str(cmd.keywords))
        return True

class CmdExit(Cmd):
    keywords = ['exit', 'quit', 'q', 'bye']

    def work(self):
        global_state.exit_requested = True
        return True

class CmdLogLevel(Cmd):
    keywords = ['log_level', 'loglevel']

    def work(self):
        loglevel = getValueFromCmdline(self.cmdline)
        if(loglevel.upper() in ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']):
            context.log_level = loglevel
            global_state.log_level = loglevel
            log.info("New log level: " + str(context.log_level))
            return True
        else:
            log.warn("Not a valid log level: " + loglevel)
            return False

class CmdListen(Cmd):
    keywords = ['listen']

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

    def work(self):
        filename = "memdump.bin"
        cmd_chunks = self.cmdline.split(' ')
        if(len(cmd_chunks) > 1):
            filename = cmd_chunks[1]

        if(os.path.exists(filename)):
            if not yesno("Overwrite '%s'?" % os.path.abspath(filename)):
                return False
        
        dump = self.getMemoryImage(refresh=True)
        f = open(filename, 'wb')
        f.write(dump)
        f.close()
        log.info("Memory dump saved in '%s'!" % os.path.abspath(filename))
        return True

class CmdSearchMem(Cmd):
    keywords = ['searchmem', 'memsearch']

    def work(self):
        cmd_chunks = self.cmdline.split(' ')
        refresh = False
        hexstring = False
        if('-r' in cmd_chunks or '--refresh' in cmd_chunks):
            refresh = True
        if('-h' in cmd_chunks or '--hex' in cmd_chunks):
            hexstring = True
        
        cmd_chunks_clean = [x for x in cmd_chunks if not x.startswith('-')]

        if(len(cmd_chunks_clean) < 2):
            raise ValueError("searchmem needs at least one argument")

        pattern = cmd_chunks_clean[1]
        if hexstring:
            try:
                pattern = pattern.decode('hex')
            except TypeError as e:
                log.warn("Search pattern cannot be converted to hexstring: " + str(e))
                return False
        
        memimage = self.getMemoryImage()
        matches = [m.start(0) for m in re.finditer(re.escape(pattern), memimage)]

        hexdumplen = (len(pattern) + 16) & 0xFFFF0
        for match in matches:
            startadr = match & 0xFFFFFFF0
            endadr = match+len(pattern)+16 & 0xFFFFFFF0
            log.info("Match at 0x%08x:" % match)
            log.hexdump(memimage[startadr:endadr], begin=startadr, highlight=pattern)
        return True

class CmdHexdump(Cmd):
    keywords = ['hexdump', 'hd']

    def work(self):
        cmd_chunks = self.cmdline.split(' ')
        if(len(cmd_chunks) < 2):
            raise ValueError("hexdump needs at least one argument")
        address = int(cmd_chunks[1],16) if cmd_chunks[1].startswith("0x") else int(cmd_chunks[1])
        length = 0x50
        if(len(cmd_chunks) > 2):
            length = int(cmd_chunks[2],16) if cmd_chunks[2].startswith("0x") else int(cmd_chunks[2])

        if not self.isAddressInSections(address, length):
            answer = yesno("Warning: Address 0x%08x (len=0x%x) is not inside a valid section. Continue?" % (address, length))
            if not answer:
                return False

        dump = self.readMem(address, address+length)

        log.hexdump(dump, begin=address)
        return True

class CmdTelescope(Cmd):
    keywords = ['telescope']

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
        cmd_chunks = self.cmdline.split(' ')
        if(len(cmd_chunks) < 2):
            raise ValueError("telescope needs at least one argument")
        address = int(cmd_chunks[1],16) if cmd_chunks[1].startswith("0x") else int(cmd_chunks[1])
        length = 0x24
        if(len(cmd_chunks) > 2):
            length = int(cmd_chunks[2],16) if cmd_chunks[2].startswith("0x") else int(cmd_chunks[2])

        dump = self.readMem(address, address + length)

        for index in range(0, len(dump)-4, 4):
            chain = self.telescope(dump[index:], 4)
            output = "0x%08x: " % (address+index)
            output += ' -> '.join(["0x%08x" % x for x in chain[:-1]])
            output += ' \"' + chain[-1] + '"'
            log.info(output)
        return True


