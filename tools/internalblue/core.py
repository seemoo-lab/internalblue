#!/usr/bin/python2

# core.py
#
# This file contains the main class of the framework which
# includes the thread functions for the receive and send thread.
# It also implements methods to setup the TCP connection to the
# Android Bluetooth stack via ADB port forwarding
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


from pwn import *
import socket
import time
import datetime
import Queue
import random

import hci


class InternalBlue():

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True'):
        context.log_level = log_level
        context.log_file = '_internalblue.log'
        context.arch = "thumb"
        self.hciport = None
        self.s_inject = None
        self.s_snoop = None
        if btsnooplog_filename != None:
            self.write_btsnooplog = True
            self.btsnooplog_file = open(btsnooplog_filename, "wb")
        else:
            self.write_btsnooplog = False
        self.recvQueue = Queue.Queue(queue_size)
        self.sendThreadrecvQueue = Queue.Queue(queue_size)
        self.sendQueue = Queue.Queue(queue_size)
        self.recvThread = None
        self.sendThread = None
        self.monitorState = None
        self.registeredHciCallbacks = []
        self.exit_requested = False
        self.monitor_exit_requested = False
        self.running = False
        self.log_level = log_level
        self.check_binutils(fix_binutils)
        self.stackDumpReceiver = None

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
            log.warn("pwntools cannot find binutils for arm architecture. Disassembling will not work!")
            return False

    def _read_btsnoop_hdr(self):
        data = self.s_snoop.recv(16)
        if(len(data) < 16):
            return None
        if(self.write_btsnooplog):
            self.btsnooplog_file.write(data)
            self.btsnooplog_file.flush()

        btsnoop_hdr = (data[:8], u32(data[8:12],endian="big"),u32(data[12:16],endian="big"))
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
                self.btsnooplog_file.flush()

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
                self.btsnooplog_file.flush()

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

                if self.sendThread != None and self.sendThread.isAlive():
                    try:
                        self.sendThreadrecvQueue.put(record, block=False)
                    except Queue.Full:
                        log.warn("recvThreadFunc: sendThread recv queue is full. dropping packets..")

                for callback in self.registeredHciCallbacks:
                    callback(record)

                if self.stackDumpReceiver.stack_dump_has_happend:
                    # A stack dump has happend!
                    log.warn("recvThreadFunc: The controller send a stack dump. stopping..")
                    self.exit_requested = True


        log.debug("Receive Thread terminated.")

    def _sendThreadFunc(self):
        log.debug("Send Thread started.")
        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # flushing recv queue to prevent it from filling up...
            try:
                while True:
                    self.sendThreadrecvQueue.get(block=False)
            except Queue.Empty:
                pass

            # Wait for packet in send queue
            try:
                task = self.sendQueue.get(timeout=0.5)
            except Queue.Empty:
                continue

            opcode, data, queue = task
            payload = p16(opcode) + p8(len(data)) + data

            # Prepend UART TYPE and length
            out = p8(hci.HCI.HCI_CMD) + p16(len(payload)) + payload
            log.debug("_sendThreadFunc: Send: " + str(out.encode('hex')))
            self.s_inject.send(out)

            while not self.exit_requested:
                # Receive response
                packet = self.recvPacket(timeout=0.5)
                if packet == None:
                    continue
                hcipkt, orig_len, inc_len, flags, drops, recvtime = packet

                if isinstance(hcipkt, hci.HCI_Event):
                    if hcipkt.event_code == 0x0e: # Cmd Complete event
                        if hcipkt.data[1:3] == p16(opcode):
                            queue.put(hcipkt.data)
                            break

        log.debug("Send Thread terminated.")

    def _setupSockets(self):
        self.hciport = random.randint(60000, 65535)     # select a random port (and hope that it is not in use)
        log.debug("_setupSockets: Selected random ports snoop=%d and inject=%d" % (self.hciport, self.hciport+1))

        saved_loglevel = context.log_level
        context.log_level = 'warn'
        try:
            adb.adb(["forward", "tcp:%d"%(self.hciport),   "tcp:8872"])
            adb.adb(["forward", "tcp:%d"%(self.hciport+1), "tcp:8873"])
        except PwnlibException as e:
            log.warn("Setup adb port forwarding failed: " + str(e))
            return False
        finally:
            context.log_level = saved_loglevel
        
        # Connect to hci injection port
        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_inject.connect(('127.0.0.1', self.hciport+1))
        self.s_inject.settimeout(0.5)

        # Connect to hci snoop log port
        self.s_snoop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_snoop.connect(('127.0.0.1', self.hciport))
        self.s_snoop.settimeout(0.5)

        # Read btsnoop header
        if(self._read_btsnoop_hdr() == None):
            log.warn("Could not read btsnoop header")
            self.s_inject.close()
            self.s_snoop.close()
            self.s_inject = self.s_snoop = None
            adb.adb(["forward", "--remove", "tcp:%d"%(self.hciport)])
            adb.adb(["forward", "--remove", "tcp:%d"%(self.hciport+1)])
            return False
        return True

    def _teardownSockets(self):
        if(self.s_inject != None):
            self.s_inject.close()
            self.s_inject = None
        if(self.s_snoop != None):
            self.s_snoop.close()
            self.s_snoop = None

        saved_loglevel = context.log_level
        context.log_level = 'warn'
        try:
            adb.adb(["forward", "--remove", "tcp:%d"%(self.hciport)])
            adb.adb(["forward", "--remove", "tcp:%d"%(self.hciport+1)])
        except PwnlibException as e:
            log.warn("Removing adb port forwarding failed: " + str(e))
            return False
        finally:
            context.log_level = saved_loglevel

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

        # Import fw depending on device
        if adb.current_device().model == 'Nexus 5':
            log.info("Importing fw for Nexus 5")
            import fw_5 as fw
        elif adb.current_device().model == 'Nexus 6P':
            log.info("Importing fw for Nexus 6P")
            import fw_6 as fw
        else:
            log.critical("Device not supported")
            return False

        # setup sockets
        if not self._setupSockets():
            log.critical("No connection to target device.")
            log.info("Check if:\n -> Bluetooth is active\n -> Bluetooth Stack has Debug Enabled\n -> BT HCI snoop log is activated\n")
            return False

        # start receive thread
        self.recvThread = context.Thread(target=self._recvThreadFunc)
        self.recvThread.setDaemon(True)
        self.recvThread.start()

        # start send thread
        self.sendThread = context.Thread(target=self._sendThreadFunc)
        self.sendThread.setDaemon(True)
        self.sendThread.start()

        # register stackDumpReceiver callback:
        self.stackDumpReceiver = hci.StackDumpReceiver()
        self.registerHciCallback(self.stackDumpReceiver.recvPacket)

        self.running = True
        return True

    def shutdown(self):
        self.exit_requested = True

        # unregister stackDumpReceiver callback:
        if self.stackDumpReceiver != None:
            self.unregisterHciCallback(self.stackDumpReceiver.recvPacket)
            self.stackDumpReceiver = None

        self.recvThread.join()
        self.sendThread.join()
        self._teardownSockets()
        if(self.write_btsnooplog):
            self.btsnooplog_file.close()
        self.running = False
        self.exit_requested = False
        log.info("Shutdown complete.")

    def registerHciCallback(self, callback):
        if callback in self.registeredHciCallbacks:
            log.warn("registerHciCallback: callback already registered!")
            return
        self.registeredHciCallbacks.append(callback)

    def unregisterHciCallback(self, callback):
        if callback in self.registeredHciCallbacks:
            self.registeredHciCallbacks.remove(callback)
            return
        log.warn("registerHciCallback: no such callback is registered!")

    def startMonitor(self, callback):
        # patch the firmware to issue hci events for each received/sent
        # LMP packet. Format of the HCI Event:
        # custom_event  len  magic  remote_bt_addr           lmp_data
        # FF            2A   _LMP_  XX:XX:XX:XX:XX:XX:00:00  ...
        if not self.check_running():
            return False
        if self.monitorState != None:
            log.warning("startMonitor: monitor is already running")
            return False

        # Injecting hooks
        hooks_code = asm(fw.INJECTED_CODE, vma=fw.HOOK_BASE_ADDRESS)
        saved_data_hooks = self.readMem(fw.HOOK_BASE_ADDRESS, len(hooks_code))
        saved_data_data  = self.readMem(fw.BUFFER_BASE_ADDRESS, fw.BUFFER_LEN)
        self.writeMem(fw.BUFFER_BASE_ADDRESS, p32(0))
        log.debug("startMonitor: injecting hook functions...")
        self.writeMem(fw.HOOK_BASE_ADDRESS, hooks_code)
        log.debug("startMonitor: inserting lmp send hook ...")
        self.writeMem(fw.LMP_SEND_PACKET_HOOK, p32(fw.HOOK_BASE_ADDRESS + 1))
        log.debug("startMonitor: inserting lmp recv hook ...")
        if not self.patchRom(fw.LMP_HANDLER, asm("b 0x%x" % (fw.HOOK_BASE_ADDRESS + 5), vma=fw.LMP_HANDLER)):
            log.warn("startMonitor: couldn't insert patch!")
            return False
        log.debug("startMonitor: monitor mode activated.")

        # Get device's BT address
        deviceAddress = self.readMem(fw.BD_ADDR, 6)[::-1]

        def hciCallbackFunction(record):
            hcipkt = record[0]
            timestamp = record[5]
            if not issubclass(hcipkt.__class__, hci.HCI_Event):
                return
            if hcipkt.event_code != 0xff:
                return
            if hcipkt.data[0:5] != "_LMP_":
                return

            sendFromDevice = hcipkt.data[5] == '\x00' # 0 for sendlmp;  1 for recvlmp
            lmpData = hcipkt.data[6:]

            connection_address = lmpData[0:6][::-1]
            connection_number = u8(lmpData[10])

            lmp_opcode = u8(lmpData[12]) >> 1
            if lmp_opcode >= 0x7C:
                lmp_opcode = u8(lmpData[13])
                lmp_len = fw.LMP_ESC_LENGTHS[lmp_opcode]
            else:
                lmp_len = fw.LMP_LENGTHS[lmp_opcode]
            lmpPacket = lmpData[12:12+lmp_len]

            src_addr = deviceAddress if sendFromDevice else connection_address
            dest_addr = deviceAddress if not sendFromDevice else connection_address
            callback(lmpPacket, sendFromDevice, src_addr, dest_addr, timestamp)


        self.registerHciCallback(hciCallbackFunction)
        self.monitorState = (
                fw.HOOK_BASE_ADDRESS,
                fw.BUFFER_BASE_ADDRESS,
                saved_data_hooks,
                saved_data_data,
                hciCallbackFunction)

        return True

    def stopMonitor(self):
        if self.monitorState == None:
            log.warning("stopMonitor: monitor is not running!")
            return False

        (fw.HOOK_BASE_ADDRESS,
        fw.BUFFER_BASE_ADDRESS,
        saved_data_hooks,
        saved_data_data,
        hciCallbackFunction) = self.monitorState
        self.monitorState = None

        self.unregisterHciCallback(hciCallbackFunction)

        # Removing hooks
        log.debug("stopMonitor: removing lmp send hook ...")
        self.writeMem(fw.LMP_SEND_PACKET_HOOK, p32(0))
        log.debug("stopMonitor: removing lmp recv hook ...")
        self.disableRomPatch(fw.LMP_HANDLER)
        log.debug("stopMonitor: Restoring saved data...")
        self.writeMem(HOOK_BASE_ADDRESS, saved_data_hooks)
        self.writeMem(BUFFER_BASE_ADDRESS, saved_data_data)
        return True

    def sendHciCommand(self, opcode, data, timeout=2):
        queue = Queue.Queue(1)
        try:
            self.sendQueue.put((opcode, data, queue), timeout=timeout)
            return queue.get(timeout=timeout)
        except Queue.Empty:
            log.warn("sendHciCommand: waiting for response timed out!")
            return None
        except Queue.Full:
            log.warn("sendHciCommand: send queue is full!")
            return None

    def recvPacket(self, timeout=None):
        if not self.check_running():
            return None

        try:
            if self.sendThread == threading.currentThread():
                return self.sendThreadrecvQueue.get(timeout=timeout)
            else:
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

            response = self.sendHciCommand(0xfc4d, p32(read_addr) + p8(blocksize))

            if response == None:
                log.warn("readMem: No response to readRAM HCI command!")
                return None

            status = ord(response[3])
            if status != 0:
                log.warning("readMem: [TODO] Got status != 0 : 0x%02X" % status)
            data = response[4:]
            outbuffer += data
            read_addr += len(data)
            byte_counter += len(data)
            if(progress_log != None):
                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, 
                        bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                progress_log.status(msg)
        return outbuffer

    def readMemAligned(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        if not self.check_running():
            return None

        if length % 4 != 0:
            log.warn("readMemAligned: length (0x%x) must be multiple of 4!" % length)
            return None

        if address % 4 != 0:
            log.warn("readMemAligned: address (0x%x) must be 4-byte aligned!" % address)
            return None

        ASM_LOCATION = 0xd7900
        ASM_SNIPPET = """
            push {r4, lr}

            mov  r0, 0xff
            mov  r1, %d      // size of the hci event payload
            add  r1, 6       // + type and length + 'READ'
            bl   0x7AFC      // malloc_hci_event_buffer
            mov  r4, r0
            add  r0, 2
            ldr  r1, =0x44414552  // 'READ'
            str  r1, [r0]
            add  r0, 4

            // copy to buffer
            ldr  r1, =0x%x
            mov  r2, %d
        loop:
            ldr  r3, [r1]
            str  r3, [r0]
            add  r0, 4
            add  r1, 4
            subs r2, 1
            bne  loop

            // send buffer
            mov r0, r4
            bl  0x398c1 // send_hci_event_without_free()

            // free buffer
            mov r0, r4
            bl  0x3FA36  // free_bloc_buffer_aligned

            pop {r4, pc}
        """

        recvQueue = Queue.Queue(1)
        def hciCallback(record):
            hcipkt = record[0]
            if not issubclass(hcipkt.__class__, hci.HCI_Event):
                return
            if hcipkt.event_code != 0xff:
                return
            if hcipkt.data[0:4] != "READ":
                return
            try:
                recvQueue.put(hcipkt.data[4:], timeout=0.5)
            except Queue.Full:
                log.warn("readMemAligned: queue is blocked. Dropping packets...")

        self.registerHciCallback(hciCallback)

        read_addr = address
        byte_counter = 0
        outbuffer = ''
        memory_type = None
        if bytes_total == 0:
            bytes_total = length
        while(read_addr < address+length):
            bytes_left = length - byte_counter
            blocksize = bytes_left
            if blocksize > 244:
                blocksize = 244

            code = asm(ASM_SNIPPET % (blocksize, read_addr, blocksize/4), vma=ASM_LOCATION)
            self.writeMem(ASM_LOCATION, code)

            if not self.launchRam(ASM_LOCATION):
                log.error("readMemAligned: launching assembler snippet failed!")
                return None

            response = None
            try:
                response = recvQueue.get(timeout=1)
            except Queue.Empty:
                log.warn("readMemAligned: No response from assembler snippet.")
                return None

            data = response
            outbuffer += data
            read_addr += len(data)
            byte_counter += len(data)
            if(progress_log != None):
                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, 
                        bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                progress_log.status(msg)

        self.unregisterHciCallback(hciCallback)
        return outbuffer

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

            response = self.sendHciCommand(0xfc4c, p32(write_addr) + data[byte_counter:byte_counter+blocksize])
            if(response[3] != '\x00'):
                log.warn("Got error code %x in command complete event." % response[3])
                return False
            write_addr += blocksize
            byte_counter += blocksize
            if(progress_log != None):
                msg = "sending data... %d / %d Bytes" % (bytes_done+byte_counter, bytes_total)
                progress_log.status(msg)
        return True

    def launchRam(self, address):
        response = self.sendHciCommand(0xfc4e, p32(address))

        if(response[3] != '\x00'):
            log.warn("Got error code %x in command complete event." % response[3])
            return False
        return True

    def getPatchramState(self):
        slot_dump       = self.readMemAligned(0x310204, 128/4)
        table_addr_dump = self.readMemAligned(0x310000, 128*4)
        table_val_dump  = self.readMem(0xd0000, 128*4)
        table_addresses = []
        table_values    = []
        slot_dwords     = []
        slot_bits       = []
        for dword in range(128/32):
            slot_dwords.append(slot_dump[dword*32:(dword+1)*32])

        for dword in slot_dwords:
            slot_bits.extend(bits(dword[::-1])[::-1])
        for i in range(128):
            if slot_bits[i]:
                table_addresses.append(u32(table_addr_dump[i*4:i*4+4])<<2)
                table_values.append(table_val_dump[i*4:i*4+4])
            else:
                table_addresses.append(None)
                table_values.append(None)
        return (table_addresses, table_values, slot_bits)

    def patchRom(self, address, patch, slot=None):
        if len(patch) != 4:
            log.warn("patchRom: patch (0x%x) must be a 32-bit dword!" % patch)
            return False

        if address % 4 != 0:
            log.warn("patchRom: Address 0x%x is not 4-byte aligned!" % address)
            return False

        table_addresses, table_values, table_slots = self.getPatchramState()

        # Check whether the address is already patched:
        for i in range(128):
            if table_addresses[i] == address:
                slot = i
                log.info("patchRom: Reusing slot for address 0x%x: %d" % (address,slot))
                # Write new value to patchram value table at 0xd0000
                self.writeMem(0xd0000 + slot*4, patch)
                return True

        if slot == None:
            # Find free slot:
            for i in range(128):
                if table_addresses[i] == None:
                    slot = i
                    log.info("patchRom: Choosing next free slot: %d" % slot)
                    break
            if slot == None:
                log.warn("patchRom: All slots are in use!")
                return False
        else:
            if table_values[slot] == 1:
                log.warn("patchRom: Slot %d is already in use. Overwriting..." % slot)

        # Write new value to patchram value table at 0xd0000
        self.writeMem(0xd0000 + slot*4, patch)

        # Write address to patchram target table at 0x31000
        self.writeMem(0x310000 + slot*4, p32(address >> 2))

        # Enable patchram slot (enable bitfield starts at 0x310204)
        # (We need to enable the slot by setting a bit in a multi-dword bitfield)
        target_dword = int(slot / 32)
        table_slots[slot] = 1
        slot_dword = unbits(table_slots[target_dword*32:(target_dword+1)*32][::-1])[::-1]
        self.writeMem(0x310204 + target_dword*4, slot_dword)
        return True

    def disableRomPatch(self, address, slot=None):
        table_addresses, table_values, table_slots = self.getPatchramState()

        if slot == None:
            if address == None:
                log.warn("disableRomPatch: address is None.")
                return False
            for i in range(128):
                if table_addresses[i] == address:
                    slot = i
                    log.info("Slot for address 0x%x is: %d" % (address,slot))
                    break
            if slot == None:
                log.warn("No slot contains address: 0x%x" % address)
                return False

        # Disable patchram slot (enable bitfield starts at 0x310204)
        # (We need to disable the slot by clearing a bit in a multi-dword bitfield)
        target_dword = int(slot / 32)
        table_slots[slot] = 0
        slot_dword = unbits(table_slots[target_dword*32:(target_dword+1)*32])
        self.writeMem(0x310204 + target_dword*4, slot_dword)

        # Write 0xFFFFC to patchram target table at 0x31000
        self.writeMem(0x310000 + slot*4, p32(0xFFFFC>>2))
        return True

    def readConnectionInformation(self, conn_number):
        if conn_number < 1 or conn_number > fw.CONNECTION_ARRAY_SIZE:
            log.warn("readConnectionInformation: connection number out of bounds: %d" % conn_number)
            return None

        connection = self.readMem(fw.CONNECTION_ARRAY_ADDRESS +
                            fw.CONNECTION_STRUCT_LENGTH*(conn_number-1),
                            fw.CONNECTION_STRUCT_LENGTH)

        if connection == b'\x00'*fw.CONNECTION_STRUCT_LENGTH:
            return None

        conn_dict = {}
        conn_dict["connection_number"]    = u32(connection[:4])
        conn_dict["remote_address"]       = connection[0x28:0x2E][::-1]
        conn_dict["remote_name_address"]  = u32(connection[0x4C:0x50])
        conn_dict["master_of_connection"] = u32(connection[0x1C:0x20]) & 1<<15 != 0
        conn_dict["connection_handle"]    = u16(connection[0x64:0x66])
        conn_dict["public_rand"]          = connection[0x78:0x88]
        #conn_dict["pin"]                  = connection[0x8C:0x92]
        #conn_dict["bt_addr_for_key"]      = connection[0x92:0x98][::-1]
        effective_key_len                 = u8(connection[0xa7:0xa8])
        conn_dict["effective_key_len"]    = effective_key_len
        conn_dict["link_key"]             = connection[0x68:0x68+effective_key_len]
        return conn_dict

    def sendLmpPacket(self, conn_nr, opcode, payload, extended_op=False):
        if conn_nr < 1 or conn_nr > fw.CONNECTION_ARRAY_SIZE:
            log.warn("sendLmpPacket: connection number out of bounds: %d" % conn_nr)
            return False

        # The TID bit will later be set in the assembler code
        opcode_data = p8(opcode<<1) if not args.ext else p8(0x7F<<1) + p8(opcode)
        data = opcode_data + payload

        CODE_BASE_ADDRESS = 0xd7500
        ASM_CODE = """
                push {r4,lr}

                // malloc buffer
                bl 0x3F17E      // malloc_0x20_bloc_buffer_memzero
                mov r4, r0

                // fill buffer
                add r0, 0xC
                ldr r1, =payload
                mov r2, 20
                bl  0x2e03c     // memcpy

                // load conn struct pointer
                mov r0, %d
                bl 0x42c04      // find connection struct from conn nr

                // set tid bit if we are the slave
                ldr r1, [r0, 0x1c]  // tid bit is at position 15 of this bitfield
                lsr r1, 15
                eor r1, 0x1         // invert the bit
                and r1, 0x1
                ldr r2, [r4, 0xC]
                orr r2, r1
                str r2, [r4, 0xC]

                mov r1, r4
                pop {r4,lr}
                b 0xf81a        // send_LMP_packet

                .align
                payload:
                """ % (conn_nr)

        asm_code_with_data = ASM_CODE + ''.join([".byte 0x%02x\n" % ord(x) 
                for x in data.ljust(20, "\x00")])
        code = asm(asm_code_with_data, vma=CODE_BASE_ADDRESS)
        self.writeMem(CODE_BASE_ADDRESS, code)

        if self.launchRam(CODE_BASE_ADDRESS):
            return True
        else:
            log.warn("sendLmpPacket: launchRam failed!")
            return False

