#!/usr/bin/python2

# brcm_bt.py
#
# This is a helper module for debugging and reversing Broadcom Bluetooth chips.
# It requires a smartphone with compatible BCM chip and patched bluetooth stack
# which is connected via adb. Also pwntools must be installed.
# Features include dumping and manipulating memory in various ways.
#
# The tool is modular and allows adding new commands in a simple way (see cmds.py)
# HCI code was partially taken from https://github.com/joekickass/python-btsnoop
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
import socket
import time
import datetime
import Queue

import hci

class BrcmBt():

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True'):
        context.log_level = log_level
        context.log_file = '_brcm_bt.log'
        context.arch = "thumb"
        self.s_inject = None
        self.s_snoop = None
        self.hci_tx = None
        if btsnooplog_filename != None:
            self.write_btsnooplog = True
            self.btsnooplog_file = open(btsnooplog_filename, "wb")
        else:
            self.write_btsnooplog = False
        self.recvQueue = Queue.Queue(queue_size)
        self.recvThread = None
        self.exit_requested = False
        self.running = False
        self.log_level = log_level
        self.check_binutils(fix_binutils)

    def check_binutils(self, fix=True):
        # Test if arm binutils is in path so that asm and disasm work:
        saved_loglevel = context.log_level
        context.log_level = 'critical'
        try:
            pwnlib.asm.which_binutils('as')
            context.log_level = saved_loglevel
            return True
        except PwnlibException:
            context.log_level = saved_loglevel
            log.debug("pwnlib.asm.which_binutils() cannot find 'as'!")
            if not fix:
                return False

        # Work around for arch (with installed arm-none-eabi-binutils)
        import os
        from glob import glob
        def which_binutils_fixed(tool):
            pattern = "arm-*-%s" % tool
            for directory in os.environ['PATH'].split(':'):
                res = sorted(glob(os.path.join(directory, pattern)))
                if res:
                    return res[0]
            raise PwnlibException("Could not find tool %s." % tool)

        try:
            which_binutils_fixed('as')
            # yeay it worked! fix it in pwnlib:
            pwnlib.asm.which_binutils = which_binutils_fixed
            log.debug("installing workaround for pwnlib.asm.which_binutils() ...")
            return True
        except PwnlibException:
            log.warn("pwntools cannot find binutils for arm architecture. Disassembing will not work!")
            return False

    def _read_btsnoop_hdr(self):
        data = self.s_snoop.recv(16)
        if(len(data) < 16):
            return None
        if(self.write_btsnooplog):
            self.btsnooplog_file.write(data)

        btsnoop_hdr = (data[:8], u32(data[8:12]),u32(data[12:16]))
        log.debug("BT Snoop Header: %s, version: %d, data link type: %d" % btsnoop_hdr)
        return btsnoop_hdr

    def _parse_time(self, time):
        """
        Record time is a 64-bit signed integer representing the time of packet arrival,
        in microseconds since midnight, January 1st, 0 AD nominal Gregorian.

        In order to avoid leap-day ambiguity in calculations, note that an equivalent
        epoch may be used of midnight, January 1st 2000 AD, which is represented in
        this field as 0x00E03AB44A676000.
        """
        time_betw_0_and_2000_ad = int("0x00E03AB44A676000", 16)
        time_since_2000_epoch = datetime.timedelta(microseconds=time) - datetime.timedelta(microseconds=time_betw_0_and_2000_ad)
        return datetime.datetime(2000, 1, 1) + time_since_2000_epoch

    def _recvThreadFunc(self):
        log.debug("Receive Thread started.")

        stackDumpReceiver = hci.StackDumpReceiver()

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            record_hdr = b''
            while(not self.exit_requested and len(record_hdr) < 24):
                try:
                    recv_data = self.s_snoop.recv(24 - len(record_hdr))
                    if len(recv_data) == 0:
                        log.info("recvThreadFunc: bt_snoop socket was closed by remote site. stopping recv thread...")
                        self.exit_requested = True
                        break
                    record_hdr += recv_data
                except socket.timeout:
                    pass # this is ok. just try again without error

            if not record_hdr or len(record_hdr) != 24:
                if not self.exit_requested:
                    log.warn("recvThreadFunc: Cannot recv record_hdr. stopping.")
                    self.exit_requested = True
                break

            if(self.write_btsnooplog):
                self.btsnooplog_file.write(record_hdr)

            orig_len, inc_len, flags, drops, time64 = struct.unpack( ">IIIIq", record_hdr)

            record_data = b''
            while(not self.exit_requested and len(record_data) < inc_len):
                try:
                    recv_data = self.s_snoop.recv(inc_len - len(record_data))
                    if len(recv_data) == 0:
                        log.info("recvThreadFunc: bt_snoop socket was closed by remote site. stopping..")
                        self.exit_requested = True
                        break
                    record_data += recv_data
                except socket.timeout:
                    pass # this is ok. just try again without error

            if not record_data or len(record_data) != inc_len:
                if not self.exit_requested:
                    log.warn("recvThreadFunc: Cannot recv data. stopping.")
                    self.exit_requested = True
                break
            
            if(self.write_btsnooplog):
                self.btsnooplog_file.write(record_data)

            try:
                parsed_time = self._parse_time(time64)
            except OverflowError:
                parsed_time = None

            record = (hci.parse_hci_packet(record_data), orig_len, inc_len, flags, drops, parsed_time)

            log.debug("Recv: [" + str(parsed_time) + "] " + str(record[0]))

            if(record != None):
                if self.recvQueue.full():
                    log.debug("recvThreadFunc: recv queue is full. flushing..")
                    try:
                        while True:
                            self.recvQueue.get(block=False)
                    except Queue.Empty:
                        pass

                try:
                    self.recvQueue.put(record, block=False)
                except Queue.Full:
                    log.warn("recvThreadFunc: recv queue is full. dropping packets..")

            if stackDumpReceiver.recvPacket(record[0]):
                # A stack dump has happend!
                log.warn("recvThreadFunc: The controller send a stack dump. stopping..")
                self.exit_requested = True

        log.debug("Receive Thread terminated.")



    def _setupSockets(self):
        saved_loglevel = context.log_level
        context.log_level = 'warn'
        try:
            adb.forward(8872)
            adb.forward(8873)
        except PwnlibException as e:
            log.warn("Setup adb port forwarding failed: " + str(e))
            return False
        finally:
            context.log_level = saved_loglevel
        
        # Connect to hci injection port
        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_inject.connect(('127.0.0.1', 8873))
        self.s_inject.settimeout(0.5)

        # Connect to hci snoop log port
        self.s_snoop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_snoop.connect(('127.0.0.1', 8872))
        self.s_snoop.settimeout(0.5)

        # Read btsnoop header
        if(self._read_btsnoop_hdr() == None):
            log.warn("Could not read btsnoop header")
            self.s_inject.close()
            self.s_snoop.close()
            self.s_inject = self.s_snoop = None
            return False
        return True

    def _teardownSockets(self):
        if(self.s_inject != None):
            self.s_inject.close()
            self.s_inject = None
        if(self.s_snoop != None):
            self.s_snoop.close()
            self.s_snoop = None

    def check_running(self):
        if self.exit_requested:
            self.shutdown()

        if not self.running:
            log.warn("Not running. call connect() first!")
            return False
        return True

    def connect(self):
        if self.exit_requested:
            self.shutdown()

        if self.running:
            log.warn("Already running. call shutdown() first!")
            return False

        # Check for connected adb devices
        adb_devices = adb.devices()
        if(len(adb_devices) == 0):
            log.critical("No adb devices found.")
            return False
        if(len(adb_devices) > 1):
            log.info("Found multiple adb devices. Please specify!")
            choice = options("Please choose:", [d.serial + ' (' + d.model + ')' for d in adb_devices])
            context.device = adb_devices[choice].serial
        else:
            log.info("Using adb device: %s (%s)" % (adb_devices[0].serial, adb_devices[0].model))
            context.device = adb_devices[0].serial

        # setup sockets
        if not self._setupSockets():
            log.critical("No connection to target device.")
            return False

        # start receive thread
        self.recvThread = context.Thread(target=self._recvThreadFunc)
        self.recvThread.setDaemon(True)
        self.recvThread.start()

        self.hci_tx = hci.HCI_TX(self.s_inject)
        self.running = True
        return True

    def shutdown(self):
        self.exit_requested = True
        self.recvThread.join()
        self._teardownSockets()
        if(self.write_btsnooplog):
            self.btsnooplog_file.close()
        self.running = False
        self.exit_requested = False
        log.info("Shutdown complete.")

    def recvPacket(self, timeout=None):
        if not self.check_running():
            return None

        try:
            return self.recvQueue.get(timeout=timeout)
        except Queue.Empty:
            return None

    def readMem(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        if not self.check_running():
            return None

        read_addr = address
        byte_counter = 0
        outbuffer = ''
        memory_type = None
        if bytes_total == 0:
            bytes_total = length
        while(read_addr < address+length):
            # Send hci frame
            bytes_left = length - byte_counter
            blocksize = bytes_left
            if blocksize > 251:
                blocksize = 251

            self.hci_tx.sendReadRamCmd(read_addr, blocksize)

            while(True):
                # Receive response
                packet = self.recvPacket(timeout=0.5)
                if packet == None:
                    if self.exit_requested or not self.running:
                        return None
                    continue
                hcipkt, orig_len, inc_len, flags, drops, recvtime = packet

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
                                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                                progress_log.status(msg)
                            break
        return outbuffer  # TODO: return memory_type

    def writeMem(self, address, data, progress_log=None, bytes_done=0, bytes_total=0):
        if not self.check_running():
            return None

        write_addr = address
        byte_counter = 0
        if bytes_total == 0:
            bytes_total = len(data)
        while(byte_counter < len(data)):
            # Send hci frame
            bytes_left = len(data) - byte_counter
            blocksize = bytes_left
            if blocksize > 251:
                blocksize = 251

            self.hci_tx.sendWriteRamCmd(write_addr, data[byte_counter:byte_counter+blocksize])

            while(True):
                # Receive response
                packet = self.recvPacket(timeout=0.5)
                if packet == None:
                    if self.exit_requested or not self.running:
                        return False
                    continue
                hcipkt, orig_len, inc_len, flags, drops, recvtime = packet

                if isinstance(hcipkt, hci.HCI_Event):
                    if(hcipkt.event_code == 0x0e): # Cmd Complete event
                        if(hcipkt.data[0:3] == '\x01\x4c\xfc'):
                            if(hcipkt.data[3] != '\x00'):
                                log.warn("Got error code %x in command complete event." % hcipkt.data[3])
                                return False
                            write_addr += blocksize
                            byte_counter += blocksize
                            if(progress_log != None):
                                msg = "sending data... %d / %d Bytes" % (bytes_done+byte_counter, bytes_total)
                                progress_log.status(msg)
                            break
        return True


    def launchRam(self, address):
        self.hci_tx.sendLaunchRamCmd(address)

        while(True):
            # Receive response
            packet = self.recvPacket(timeout=1.5) # TODO
            if packet == None:
                if self.exit_requested or not self.running:
                    return False
                continue
            hcipkt, orig_len, inc_len, flags, drops, recvtime = packet

            if isinstance(hcipkt, hci.HCI_Event):
                if(hcipkt.event_code == 0x0e): # Cmd Complete event
                    if(hcipkt.data[0:3] == '\x01\x4e\xfc'):
                        if(hcipkt.data[3] != '\x00'):
                            log.warn("Got error code %x in command complete event." % hcipkt.data[3])
                            return False
                        break
        return True

