#!/usr/bin/env python2

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

from abc import ABCMeta, abstractmethod

from pwn import *
import socket
import time
import datetime
import Queue
import random

import hci


class InternalBlue():
    __metaclass__ = ABCMeta

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        context.log_level = log_level
        context.log_file = data_directory + '/_internalblue.log'
        context.arch = "thumb"

        self.interface = None   # holds the context.device / hci interaface which is used to connect, is set in cli
        self.fw = None          # holds the firmware file


        self.data_directory = data_directory
        self.hciport = None     # hciport is the port number of the forwarded HCI snoop port (8872). The inject port is at hciport+1
        self.s_inject = None    # This is the TCP socket to the HCI inject port
        self.s_snoop = None     # This is the TCP socket to the HCI snoop port

        # If btsnooplog_filename is set, write all incomming HCI packets to a file (can be viewed in wireshark for debugging)
        if btsnooplog_filename != None:
            self.write_btsnooplog = True
            self.btsnooplog_file = open(self.data_directory + "/" + btsnooplog_filename, "wb")
        else:
            self.write_btsnooplog = False

        # The sendQueue connects the core framework to the sendThread. With the
        # function sendHciCommand, the core framework (or a CLI command / user script)
        # can put a HCI Command into this queue. The queue entry should be a tuple:
        # (opcode, data, response_queue)
        #   - opcode: The HCI opcode (16 bit integer)
        #   - data:   The HCI payload (byte string)
        #   - response_queue: queue that is used for delivering the HCI response
        #                     back to the entity that put the HCI command into the
        #                     sendQueue.
        # The sendThread polls the queue, gets the above mentioned tuple, sends the
        # HCI command to the firmware and then waits for the response from the
        # firmware. Once the response arrived, it puts the response into the
        # response_queue from the tuple. See sendHciCommand().
        self.sendQueue = Queue.Queue(queue_size)

        self.recvThread = None                  # The thread which is responsible for the HCI snoop socket
        self.sendThread = None                  # The thread which is responsible for the HCI inject socket

        self.lmpMonitorState = None             # A tuple which stores state information for the LMP monitor mode (see startLmpMonitor())

        self.tracepoints = []                   # A list of currently active tracepoints 
                                                # The list contains tuples:
                                                # [0] target address
                                                # [1] address of the hook code
        self.tracepoint_registers       = None  # Last captured register values from a tracepoint
        self.tracepoint_memdump_parts   = {}    # Last captured RAM dump from a tracepoint
        self.tracepoint_memdump_address = None  # Start address of the RAM dump

        # The registeredHciCallbacks list holds callback functions which are being called by the
        # recvThread once a HCI Event is being received. Use registerHciCallback() for registering
        # a new callback (put it in the list) and unregisterHciCallback() for removing it again.
        self.registeredHciCallbacks = []

        # The registeredHciRecvQueues list holds queues which are being filled by the
        # recvThread once a HCI Event is being received. Use registerHciRecvQueue() for registering
        # a new queue (put it in the list) and unregisterHciRecvQueue() for removing it again.
        # Actually the registeredHciRecvQueues holds tuples with the format: (queue, filter_function)
        # filter_function will be called for each packet that is received and only if it returns
        # True, the packet will be put into the queue. The filter_function can be None in order
        # to put all packets into the queue.
        self.registeredHciRecvQueues = []

        self.exit_requested = False             # Will be set to true when the framework wants to shut down (e.g. on error or user exit)
        self.running = False                    # 'running' is True once the connection to the HCI sockets is established
                                                # and the recvThread and sendThread are started (see connect() and shutdown())
        self.log_level = log_level

        self.check_binutils(fix_binutils)       # Check if ARM binutils are installed (needed for asm() and disasm())
                                                # If fix_binutils is True, the function tries to fix the error were
                                                # the binutils are installed but not found by pwntools (e.g. under Arch Linux)

        self.stackDumpReceiver = None           # This class will monitor the HCI Events and detect stack trace events.

        # Register callbacks which handle specific HCI Events:
        self.registerHciCallback(self.connectionStatusCallback)

    def check_binutils(self, fix=True):
        """
        Test if ARM binutils is in path so that asm and disasm (provided by
        pwntools) work correctly.
        It may happen, that ARM binutils are installed but not found by pwntools.
        If 'fix' is True, check_binutils will try to fix this.
        """

        saved_loglevel = context.log_level
        context.log_level = 'critical'
        try:
            pwnlib.asm.which_binutils('as')     # throws PwnlibException if as cannot be found
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
        """
        Read the btsnoop header (see RFC 1761) from the snoop socket (s_snoop).
        """

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
        Taken from: https://github.com/joekickass/python-btsnoop

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
        """
        This is the run-function of the recvThread. It receives HCI events from the
        s_snoop socket. The HCI packets are encapsulated in btsnoop records (see RFC 1761).
        Received HCI packets are being put into the queues inside registeredHciRecvQueues and
        passed to the callback functions inside registeredHciCallbacks.
        The thread stops when exit_requested is set to True. It will do that on its own
        if it encounters a fatal error or the stackDumpReceiver reports that the chip crashed.
        """

        log.debug("Receive Thread started.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # Read the record header
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
                except AttributeError:
                    #FIXME bt_snoop socket not properly working for hcitool
                    sleep(1)
                    pass

            if not record_hdr or len(record_hdr) != 24:
                if not self.exit_requested:
                    log.warn("recvThreadFunc: Cannot recv record_hdr. stopping.")
                    self.exit_requested = True
                break

            if(self.write_btsnooplog):
                self.btsnooplog_file.write(record_hdr)
                self.btsnooplog_file.flush()

            orig_len, inc_len, flags, drops, time64 = struct.unpack( ">IIIIq", record_hdr)

            # Read the record data
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

            # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
            record = (hci.parse_hci_packet(record_data), orig_len, inc_len, flags, drops, parsed_time)

            log.debug("Recv: [" + str(parsed_time) + "] " + str(record[0]))

            # Put the record into all queues of registeredHciRecvQueues if their
            # filter function matches.
            for queue, filter_function in self.registeredHciRecvQueues:
                if filter_function == None or filter_function(record):
                    try:
                        queue.put(record, block=False)
                    except Queue.Full:
                        log.warn("recvThreadFunc: A recv queue is full. dropping packets..")

            # Call all callback functions inside registeredHciCallbacks and pass the
            # record as argument.
            for callback in self.registeredHciCallbacks:
                callback(record)

            # Check if the stackDumpReceiver has noticed that the chip crashed.
            if self.stackDumpReceiver.stack_dump_has_happend:
                # A stack dump has happend!
                log.warn("recvThreadFunc: The controller send a stack dump. stopping..")
                self.exit_requested = True

        log.debug("Receive Thread terminated.")

    def _sendThreadFunc(self):
        """
        This is the run-function of the sendThread. It polls the sendQueue for new 'send tasks'
        and executes them (sends HCI commands to the chip and returns the response).
        The entries of the sendQueue are tuples representing a 'send task':
         (opcode, data, response_queue)
           - opcode: The HCI opcode (16 bit integer) to send
           - data:   The HCI payload (byte string) to send
           - response_queue: queue that is used for delivering the HCI response
                             back to the entity that put the HCI command into the
                             sendQueue.
        Use sendHciCommand() to put 'send tasks' into the sendQueue!
        The thread stops when exit_requested is set to True.
        """

        log.debug("Send Thread started.")
        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # Wait for 'send task' in send queue
            try:
                task = self.sendQueue.get(timeout=0.5)
            except Queue.Empty:
                continue

            # Extract the components of the task and build the HCI command
            opcode, data, queue = task
            payload = p16(opcode) + p8(len(data)) + data

            # Prepend UART TYPE and length
            out = p8(hci.HCI.HCI_CMD) + p16(len(payload)) + payload

            # register queue to receive the response
            recvQueue = Queue.Queue(1)
            def recvFilterFunction(record):
                hcipkt = record[0]

                if not isinstance(hcipkt, hci.HCI_Event):
                    return False

                if hcipkt.event_code == 0x0e:   # Cmd Complete event
                    if hcipkt.data[1:3] == p16(opcode):
                        return True

                if hcipkt.event_code == 0x0f:   # Cmd Status event
                    if hcipkt.data[2:4] == p16(opcode):
                        return True
                return False

            self.registerHciRecvQueue(recvQueue, recvFilterFunction)

            # Send command to the chip using s_inject socket
            log.debug("_sendThreadFunc: Send: " + str(out.encode('hex')))
            self.s_inject.send(out)

            # Wait for the HCI event response by polling the recvQueue
            try:
                record = recvQueue.get(timeout=2)
                hcipkt = record[0]
                data   = hcipkt.data
            except Queue.Empty:
                log.warn("_sendThreadFunc: No response from the firmware.")
                data = None
                self.unregisterHciRecvQueue(recvQueue)
                continue

            queue.put(data)
            self.unregisterHciRecvQueue(recvQueue)

        log.debug("Send Thread terminated.")

    def _setupSockets(self):
        """
        Forward the HCI snoop and inject ports from the Android device to
        the host (using adb). Open TCP sockets (s_snoop, s_inject) to connect
        to the forwarded ports. Read the btsnoop header from the s_snoop
        socket in order to verify that the connection actually works correctly.
        """

        # In order to support multiple parallel instances of InternalBlue
        # (with multiple attached Android devices) we must not hard code the
        # forwarded port numbers. Therefore we choose the port numbers
        # randomly and hope that they are not already in use.
        self.hciport = random.randint(60000, 65535)
        log.debug("_setupSockets: Selected random ports snoop=%d and inject=%d" % (self.hciport, self.hciport+1))

        # Forward ports 8872 and 8873. Ignore log.info() outputs by the adb function.
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
        """
        Close s_snoop and s_inject sockets. Remove port forwarding with adb.
        """

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

    def _tracepointHciCallbackFunction(self, record):
        hcipkt = record[0]      # get HCI Event packet
        timestamp = record[5]   # get timestamp

        # Check if event contains a tracepoint packet
        if not issubclass(hcipkt.__class__, hci.HCI_Event):
            return
        if hcipkt.event_code != 0xff:   # must be custom event (0xff)
            return

        if hcipkt.data[0:6] == "TRACE_": # My custom header (see hook code)
            data = hcipkt.data[6:]
            self.tracepoint_registers = [u32(data[i:i+4]) for i in range(0, 68, 4)]
            pc = self.tracepoint_registers[0]
            registers  = "pc:  0x%08x   lr:  0x%08x   sp:  0x%08x   cpsr: 0x%08x\n" % \
                        (pc, self.tracepoint_registers[16], self.tracepoint_registers[1], self.tracepoint_registers[2])
            registers += "r0:  0x%08x   r1:  0x%08x   r2:  0x%08x   r3:  0x%08x   r4:  0x%08x\n" % \
                        tuple(self.tracepoint_registers[3:8])
            registers += "r5:  0x%08x   r6:  0x%08x   r7:  0x%08x   r8:  0x%08x   r9:  0x%08x\n" % \
                        tuple(self.tracepoint_registers[8:13])
            registers += "r10: 0x%08x   r11: 0x%08x   r12: 0x%08x\n" % \
                        tuple(self.tracepoint_registers[13:16])
            log.info("Tracepoint 0x%x was hit and deactivated:\n" % pc + registers)
            
            filename = self.data_directory + "/" + "internalblue_tracepoint_registers_%s.bin" % datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            log.info("Captured Registers for Tracepoint to %s" % filename)
            f = open(filename, "w")
            f.write(registers)
            f.close()

            # remove tracepoint from self.tracepoints
            for tp in self.tracepoints:
                if tp[0] == pc:
                    self.tracepoints.remove(tp)
                    break

            # reset all RAM dump related variables:
            self.tracepoint_memdump_address = None
            self.tracepoint_memdump_parts = {}


        elif hcipkt.data[0:6] == "RAM___": # My custom header (see hook code)
            dump_address = u32(hcipkt.data[6:10])
            data = hcipkt.data[10:]

            if self.tracepoint_memdump_address == None:
                self.tracepoint_memdump_address = dump_address
            normalized_address = dump_address - self.tracepoint_memdump_address 
            self.tracepoint_memdump_parts[normalized_address] = data

            # Check if this was the last packet
            if len(self.tracepoint_memdump_parts) == self.fw.TRACEPOINT_RAM_DUMP_PKT_COUNT:
                dump = fit(self.tracepoint_memdump_parts)
                #TODO: use this to start qemu
                filename = self.data_directory + "/" + "internalblue_tracepoint_0x%x_%s.bin" % (self.tracepoint_memdump_address, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
                log.info("Captured Ram Dump for Tracepoint 0x%x to %s" % (self.tracepoint_memdump_address, filename))
                f = open(filename, "wb")
                f.write(dump)
                f.close()


    def addTracepoint(self, address):
        # Check if constants are defined in fw.py
        for const in ['TRACEPOINT_BODY_ASM_LOCATION', 'TRACEPOINT_BODY_ASM_SNIPPET',
                      'TRACEPOINT_HOOK_ASM', 'TRACEPOINT_HOOKS_LOCATION',
                      'TRACEPOINT_HOOK_SIZE']:
            if const not in dir(self.fw):
                log.warn("addTracepoint: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        if not self.check_running():
            return False

        #FIXME: Currently only works for aligned addresses
        if address % 4 != 0:
            log.warn("Only tracepoints at aligned addresses are allowed!")
            return False

        # Check if tracepoint exists
        existing_hook_addresses = []
        for tp_address, tp_hook_address in self.tracepoints:
            existing_hook_addresses.append(tp_hook_address)
            if tp_address == address:
                log.warn("Tracepoint at 0x%x does already exist!" % address)
                return False

        # we only have room for 0x90/28 = 5 tracepoints
        if len(self.tracepoints) >= 5:
            log.warn("Already using the maximum of 5 tracepoints")
            return False

        # Find a free address for the hook code
        for i in range(5):
            hook_address = self.fw.TRACEPOINT_HOOKS_LOCATION + self.fw.TRACEPOINT_HOOK_SIZE*i
            if hook_address not in existing_hook_addresses:
                break

        # Check if this is the first tracepoint
        if self._tracepointHciCallbackFunction not in self.registeredHciCallbacks:
            log.info("Initial tracepoint: setting up tracepoint engine.")

            # compile assembler snippet containing the hook body code:
            hooks_code = asm(self.fw.TRACEPOINT_BODY_ASM_SNIPPET, vma=self.fw.TRACEPOINT_BODY_ASM_LOCATION, arch='thumb')
            if len(hooks_code) > 0x100:
                log.error("Assertion failed: len(hooks_code)=%d  is larger than 0x100!" % len(hooks_code))

            # save memory content at the addresses where we place the snippet and the stage-1 hooks
            self.tracepoint_saved_data = self.readMem(self.fw.TRACEPOINT_BODY_ASM_LOCATION, 0x100)

            # write code for hook to memory
            self.writeMem(self.fw.TRACEPOINT_BODY_ASM_LOCATION, hooks_code)

            # Register tracepoint hci callback function
            self.registerHciCallback(self._tracepointHciCallbackFunction)

        # Add tracepoint to list
        self.tracepoints.append((address, hook_address))

        ### Injecting stage-1 hooks ###
        # save the 4 bytes at which the hook branch (e.g. b <hook address>) will be placed
        saved_instructions = self.readMem(address, 4)

        # we need to know the patchram slot in advance..
        # little trick/hack: we just insert a patch now with the original data to
        # receive the slot value. later we insert the actual patch which will reuse
        # the same slot.
        # FIXME: To increase performance, try to not do it like that ^^
        self.patchRom(address, saved_instructions)
        table_addresses, _, _ = self.getPatchramState()
        patchram_slot = table_addresses.index(address)
        log.info("Using patchram slot %d for tracepoint." % patchram_slot)

        # compile assembler snippet containing the stage-1 hook code:
        stage1_hook_code = asm(self.fw.TRACEPOINT_HOOK_ASM % (address, patchram_slot,
            self.fw.TRACEPOINT_BODY_ASM_LOCATION, address), vma=hook_address, arch='thumb')

        if len(stage1_hook_code) > self.fw.TRACEPOINT_HOOK_SIZE:
            log.error("Assertion failed: len(stage1_hook_code)=%d  is larger than TRACEPOINT_HOOK_SIZE!" % len(stage1_hook_code))
            return False

        # write code for hook to memory
        log.debug("addTracepoint: injecting hook function...")
        self.writeMem(hook_address, stage1_hook_code)

        # patch in the hook branch instruction
        patch = asm("b 0x%x" % hook_address, vma=address, arch='thumb')
        if not self.patchRom(address, patch):
            log.warn("addTracepoint: couldn't insert tracepoint hook!")
            return False

        log.debug("addTracepoint: Placed Tracepoint at 0x%08x (hook at 0x%x)." % (address, hook_address))
        return True

    def deleteTracepoint(self, address):
        if not self.check_running():
            return False

        # find tracepoint in the list
        for tp in self.tracepoints:
            if tp[0] == address:
                # disable patchram slot for the tracepoint
                self.disableRomPatch(tp[0])

                # remove tracepoint from self.tracepoints
                self.tracepoints.remove(tp)
                break
        else:
            log.warn("deleteTracepoint: No tracepoint at address: 0x%x" % address)
            return False

        return True

    def check_running(self):
        """
        Check if the framework is running (i.e. the sockets are connected,
        the recv and send threads are running and exit_requested is not True)
        """

        if self.exit_requested:
            self.shutdown()

        if not self.running:
            log.warn("Not running. call connect() first!")
            return False
        return True

    @abstractmethod
    def device_list(self):
        pass

    def connect(self):

        if self.exit_requested:
            self.shutdown()

        if self.running:
            log.warn("Already running. call shutdown() first!")
            return False

        if not self.interface:
            log.warn("No adb device identifier is set")
            return False

        if not self.local_connect():
            return False

        log.info('Connected to %s', self.interface)

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

        # register hci callback:
        self.registerHciCallback(self.stackDumpReceiver.recvPacket)
        
        self.initialize_fimware()

        self.running = True

        return True

    def local_connect(self):
        return True
    
    def initialize_fimware(self):
        """
        Checks if we are running on a Broadcom chip and loads available firmware information based
        on LMP subversion.
        """
        
        global fw    # put the imported fw into global namespace #FIXME does not work for adbcmds.py

        # send Read_Local_Version_Information
        version = self.sendHciCommand(0x1001, '')
        # Broadcom uses 0x000f as vendor ID
        if (u8(version[9]) != 0x00 or u8(version[8]) != 0x0f):
            log.critical("Not running on a Broadcom chip!")
        else:
            log.info("Broadcom chip detected.")
            subversion = (u8(version[11]) << 8) + u8(version[10])
            # get LMP Subversion
            log.info("Chip identifier (LMP subversion): 0x%04x" % subversion)
            
            # TODO move this to a generic firmware file
            if   (subversion == 0x6109): # Nexus 5, Xperia Z3, Samsung Galaxy Note 3
                import fw_5 as fw
                log.info("Loaded firmware information for BCM4335C0.")
            elif (subversion == 0x6119): # Raspberry Pi 3+
                import fw_rpi3p as fw #TODO rpi3/rpi3+ are different, update this along with the firmware file
                log.info("Laoded firmware information for BCM4345C0.")
            elif (subversion == 0x240f): # Nexus 6P
                import fw_6p as fw
                log.info("Loaded firmware information for BCM4358A3.")
        
        try:
            self.fw = fw    # Other scripts (such as adbcmds.py) can use fw through a member variable
        except:
            import fw_rpi3 as fw #TODO default empty firmware
            self.fw = fw
            log.warn("Loaded default firmware information, some commands will not be supported.")            
            
        return True

    def shutdown(self):
        """
        Shutdown the framework by stopping the send and recv threads and calling the local_shutdown function.
        """

        # Setting exit_requested to True will stop the send and recv threads at their
        # next while loop iteration
        self.exit_requested = True

        # unregister stackDumpReceiver callback:
        if self.stackDumpReceiver != None:
            self.stackDumpReceiver = None

        # Call local_shutdown
        self.local_shutdown()

        if (self.write_btsnooplog):
            self.btsnooplog_file.close()

        self.running = False
        self.exit_requested = False
        log.info("Shutdown complete.")

    def local_shutdown(self):
        pass

    def registerHciCallback(self, callback):
        """
        Add a new callback function to self.registeredHciCallbacks.
        The function will be called every time the recvThread receives
        a HCI packet. The packet will be passed to the callback function
        as first argument. The format is a tuple containing:
        - HCI packet (subclass of HCI, see hci.py)
        - original length
        - inc_len
        - flags
        - drops
        - timestamp (python datetime object)
        """

        if callback in self.registeredHciCallbacks:
            log.warn("registerHciCallback: callback already registered!")
            return
        self.registeredHciCallbacks.append(callback)

    def unregisterHciCallback(self, callback):
        """
        Remove a callback function from self.registeredHciCallbacks.
        """

        if callback in self.registeredHciCallbacks:
            self.registeredHciCallbacks.remove(callback)
            return
        log.warn("registerHciCallback: no such callback is registered!")

    def registerHciRecvQueue(self, queue, filter_function=None):
        """
        Add a new queue to self.registeredHciRecvQueues.
        The queue will be filled by the recvThread every time the thread receives
        a HCI packet.  The format of the packet is a tuple containing:
        - HCI packet (subclass of HCI, see hci.py)
        - original length
        - inc_len
        - flags
        - drops
        - timestamp (python datetime object)

        If filter_function is not None, the tuple will first be passed
        to the function and only if the function returns True, the packet
        is put into the queue.
        """

        if queue in self.registeredHciRecvQueues:
            log.warn("registerHciRecvQueue: queue already registered!")
            return
        self.registeredHciRecvQueues.append((queue, filter_function))

    def unregisterHciRecvQueue(self, queue):
        """
        Remove a queue from self.registeredHciRecvQueues.
        """

        for entry in self.registeredHciRecvQueues:
            if entry[0] == queue:
                self.registeredHciRecvQueues.remove(entry)
                return
        log.warn("registerHciRecvQueue: no such queue is registered!")

    def startLmpMonitor(self, callback):
        """
        Start the LMP monitor. The callback function will be called for every
        sent or received LMP packet. The following arguments are passed to
        the callback function:
        - lmpPacket (starting with the lmp opcode, byte-string)
        - sendFromDevice (True if the LMP packet originated from the own device)
        - src_addr (BT source address, byte-string of size 6)
        - dest_addr (BT destination address, byte-string of size 6)
        - timestamp (time of arrival for the HCI event, datetime object)

        How it works:
        It patches the firmware to issue HCI events for each received/sent
        LMP packet. Format of this HCI Event (see also the patch code in fw.py):
        custom_event  len  magic  remote_bt_addr           conn_nr      LMP packet
        FF            2C   _LMP_  XX:XX:XX:XX:XX:XX:00:00  00:00:0X:00  <opcode>...
        """

        # Check if constants are defined in fw.py
        for const in ['LMP_SEND_PACKET_HOOK', 'LMP_MONITOR_LMP_HANDLER_ADDRESS',
                      'LMP_MONITOR_HOOK_BASE_ADDRESS', 'LMP_MONITOR_INJECTED_CODE']:
            if const not in dir(self.fw):
                log.warn("startLmpMonitor: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        if not self.check_running():
            return False
        if self.lmpMonitorState != None:
            log.warning("startLmpMonitor: monitor is already running")
            return False

        ### Injecting hooks ###
        # compile assembler snippet containing the hook code:
        hooks_code = asm(self.fw.LMP_MONITOR_INJECTED_CODE, vma=self.fw.LMP_MONITOR_HOOK_BASE_ADDRESS, arch='thumb')
        # save memory content at the addresses where we place the snippet and the temp. buffer
        saved_data_hooks = self.readMem(self.fw.LMP_MONITOR_HOOK_BASE_ADDRESS, len(hooks_code))
        saved_data_data = ""
        if 'LMP_MONITOR_BUFFER_BASE_ADDRESS' in dir(self.fw):
            saved_data_data  = self.readMem(self.fw.LMP_MONITOR_BUFFER_BASE_ADDRESS, self.fw.LMP_MONITOR_BUFFER_LEN)

        # write code for hook to memory (hook_send_lmp, hook_recv_lmp)
        log.debug("startLmpMonitor: injecting hook functions...")
        self.writeMem(self.fw.LMP_MONITOR_HOOK_BASE_ADDRESS, hooks_code)

        # The LMP_send_packet function has the option to define a hook in RAM
        log.debug("startLmpMonitor: inserting lmp send hook ...")
        self.writeMem(self.fw.LMP_SEND_PACKET_HOOK, p32(self.fw.LMP_MONITOR_HOOK_BASE_ADDRESS + 1))
        
        # The LMP_dispatcher function needs a ROM patch for inserting a hook
        log.debug("startLmpMonitor: inserting lmp recv hook ...")
        # position of 'b hook_recv_lmp' within hook code is + 5
        patch = asm("b 0x%x" % (self.fw.LMP_MONITOR_HOOK_BASE_ADDRESS + 5), vma=self.fw.LMP_MONITOR_LMP_HANDLER_ADDRESS, arch='thumb')
        if not self.patchRom(self.fw.LMP_MONITOR_LMP_HANDLER_ADDRESS, patch):
            log.warn("startLmpMonitor: couldn't insert patch!")
            return False
        log.debug("startLmpMonitor: monitor mode activated.")

        # Get device's BT address
        deviceAddress = self.readMem(self.fw.BD_ADDR, 6)[::-1]

        # define a callback function that gets called every time a HCI event is received.
        # It checks whether the event contains a LMP packet, extracts the LMP packet and 
        # calls the callback function which was supplied to startLmpMonitor()
        def hciCallbackFunction(record):
            hcipkt = record[0]      # get HCI Event packet
            timestamp = record[5]   # get timestamp

            # Check if event contains a LMP packet
            if not issubclass(hcipkt.__class__, hci.HCI_Event):
                return
            if hcipkt.event_code != 0xff:   # must be custom event (0xff)
                return
            if hcipkt.data[0:5] != "_LMP_": # My custom header (see hook code)
                return

            # My custom header contains a field that indicates whether the packet
            # was intercepted from LMP_dispatcher or LMP_send_packet
            sendFromDevice = hcipkt.data[5] == '\x00'   # 0 for send;  1 for recv
            lmpData = hcipkt.data[6:]                   # grab the data which comes after my header
            
            connection_address = lmpData[0:6][::-1]     # The BT address of the remote device
                                                        # stored in little endian byte order
            connection_number = u8(lmpData[10])         # not used, but may be useful..

            lmp_opcode = u8(lmpData[12]) >> 1           # LSB of this byte is the TID (transaction ID)
                                                        # The rest is the LMP opcode
            if lmp_opcode >= 0x7C:
                # This is a escape opcode. The actual opcode is stored in the next byte
                lmp_opcode = u8(lmpData[13])
                if lmp_opcode < len(self.fw.LMP_ESC_LENGTHS):
                    lmp_len = self.fw.LMP_ESC_LENGTHS[lmp_opcode]
                else:
                    log.debug("startLmpMonitor.hciCallbackFunction: received unknown esc. LMP opcode!")
                    lmp_len = 17 # Asume max length
            elif lmp_opcode == 0:
                lmp_opcode = u8(lmpData[13])
                if lmp_opcode < len(self.fw.LMP_VSC_LENGTHS):
                    lmp_len = self.fw.LMP_VSC_LENGTHS[lmp_opcode]
                else:
                    lmp_len = 17
            elif lmp_opcode < len(self.fw.LMP_LENGTHS):
                lmp_len = self.fw.LMP_LENGTHS[lmp_opcode]
            else:
                log.debug("startLmpMonitor.hciCallbackFunction: received unknown LMP opcode!")
                lmp_len = 17 # Asume max length

            lmpPacket = lmpData[12:12+lmp_len]          # Extract the LMP packet (incuding the opcode)

            # set src and dest address based on whether the packet was sent to a remote device or
            # received from a remote device
            src_addr = deviceAddress if sendFromDevice else connection_address
            dest_addr = deviceAddress if not sendFromDevice else connection_address

            # pass the information to the callback function
            callback(lmpPacket, sendFromDevice, src_addr, dest_addr, timestamp)


        # register our HCI callback function so it gets called by the receive thread every time a
        # HCI packet is received
        self.registerHciCallback(hciCallbackFunction)

        # store some information which is used inside stopLmpMonitor()
        self.lmpMonitorState = (saved_data_hooks, saved_data_data, hciCallbackFunction)

        return True

    def stopLmpMonitor(self):
        """
        Stop the LMP monitor mode. This will undo all patches / hooks.
        """

        # Check if constants are defined in fw.py
        for const in ['LMP_SEND_PACKET_HOOK', 'LMP_MONITOR_LMP_HANDLER_ADDRESS',
                      'LMP_MONITOR_HOOK_BASE_ADDRESS']:
            if const not in dir(self.fw):
                log.warn("stopLmpMonitor: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        if self.lmpMonitorState == None:
            log.warning("stopLmpMonitor: monitor is not running!")
            return False

        # Retrive stored information (was stored at the end of startLmpMonitor()
        (saved_data_hooks, saved_data_data, hciCallbackFunction) = self.lmpMonitorState
        self.lmpMonitorState = None

        # stop processing HCI packets for the monitor
        self.unregisterHciCallback(hciCallbackFunction)

        # Removing hooks
        log.debug("stopLmpMonitor: removing lmp send hook ...")
        self.writeMem(self.fw.LMP_SEND_PACKET_HOOK, p32(0))
        log.debug("stopLmpMonitor: removing lmp recv hook ...")
        self.disableRomPatch(self.fw.LMP_MONITOR_LMP_HANDLER_ADDRESS)

        # Restoring the memory content of the area where we stored the patch code and temp. buffers
        log.debug("stopLmpMonitor: Restoring saved data...")
        self.writeMem(self.fw.LMP_MONITOR_HOOK_BASE_ADDRESS, saved_data_hooks)
        if 'LMP_MONITOR_BUFFER_BASE_ADDRESS' in dir(self.fw):
            self.writeMem(self.fw.LMP_MONITOR_BUFFER_BASE_ADDRESS, saved_data_data)
        return True

    @abstractmethod
    def sendHciCommand(self, opcode, data, timeout=2):
        pass

    def recvPacket(self, timeout=None):
        """
        This function polls the recvQueue for the next available HCI
        packet and returns it. The function checks whether it is called
        from the sendThread or any other thread and respectively chooses
        either the sendThreadrecvQueue or the recvQueue.

        The recvQueue is filled by the recvThread. If the queue fills up
        the recvThread empties the queue (unprocessed packets are lost).
        The recvPacket function is meant to receive raw HCI packets in
        a blocking manner. Consider using the registerHciCallback()
        functionality as an alternative which works asynchronously.
        """

        if not self.check_running():
            return None

        try:
            return self.recvQueue.get(timeout=timeout)
        except Queue.Empty:
            return None

    def readMem(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        """
        Reads <length> bytes from the memory space of the firmware at the given
        address. Reading from unmapped memory or certain memory-mapped-IO areas
        which need aligned access crashes the chip.

        Optional arguments for progress logs:
        - progress_log: An instance of log.progress() which will be updated during the read.
        - bytes_done:   Number of bytes that have already been read with earlier calls to
                        readMem() and belonging to the same transaction which is covered by progress_log.
        - bytes_total:  Total bytes that will be read within the transaction covered by progress_log.
        """

        log.debug("readMem: reading at 0x%x" % address)
        if not self.check_running():
            return None

        read_addr = address         # read_addr is the address of the next Read_RAM HCI command
        byte_counter = 0            # tracks the number of received bytes
        outbuffer = ''              # buffer which stores all accumulated data read from the chip
        if bytes_total == 0:        # If no total bytes where given just use length
            bytes_total = length        
        retry = True                # Retry once on failures
        while(read_addr < address+length):  # Send HCI Read_RAM commands until all data is received
            # Send hci frame
            bytes_left = length - byte_counter
            blocksize = bytes_left
            if blocksize > 251:     # The max. size of a Read_RAM payload is 251
                blocksize = 251

            # Send Read_RAM (0xfc4d) command
            response = self.sendHciCommand(0xfc4d, p32(read_addr) + p8(blocksize))

            if (response == None or response == False):
                log.warning("readMem: No response to readRAM HCI command! (read_addr=%x, len=%x)" % (read_addr, length))
                # Retry once...
                if retry:
                    log.debug("readMem: retrying once...")
                    retry = False
                    continue
                else:
                    log.warning("readMem: failed!")
                    return None

            status = ord(response[3])
            if status != 0:
                # It is not yet reverse engineered what this byte means. For almost
                # all memory addresses it will be 0. But for some it will be different,
                # EDIT: response should be a command complete event (event code 0x0e). The 4 byte (response[3]) indicates the hci error code
                #       0x00 (0) means everything okay
                #       0x12 means Command Disallowed
                # e.g. for address 0xff000000 (aka 'EEPROM') it is 0x12
                log.warning("readMem: [TODO] Got status != 0 : error 0x%02X" % status)
            data = response[4:]         # start of the actual data is at offset 4
            outbuffer += data
            
            if (len(data) == 0): #this happens i.e. if not called on a brcm chip
                log.warn("readMem: empty response, quitting...")
                break
            
            read_addr += len(data)
            byte_counter += len(data)
            if(progress_log != None):
                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, 
                        bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                progress_log.status(msg)
            retry = True # this round worked, so we re-enable this flag 
        return outbuffer

    def readMemAligned(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        """
        This is an alternative to readMem() which enforces a strictly aligned access
        to the memory that is read. This is needed for e.g. the memory-mapped-IO
        section at 0x310000 (patchram) and possibly other sections as well.
        The arguments are equivalent to readMem() except that the address and length
        have to be 4-byte aligned.

        The current implementation works like this (and obviously can be improved!):
        - Work in chunks of max. 244 bytes (restricted by max. size of HCI event)
        - For each chunk do:
          - Write a code snippet to the firmware which copies the chunk of memory
            into a custom HCI Event and sends it to the host (this uses aligned
            ldr and str instructions)
          - Register a hciCallbackFunction for receiving the custom event
        """

        # Check if constants are defined in fw.py
        for const in ['READ_MEM_ALIGNED_ASM_LOCATION', 'READ_MEM_ALIGNED_ASM_SNIPPET']:
            if const not in dir(self.fw):
                log.warn("readMemAligned: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        if not self.check_running():
            return None

        # Force length to be multiple of 4 (needed for strict alignment)
        if length % 4 != 0:
            log.warn("readMemAligned: length (0x%x) must be multiple of 4!" % length)
            return None

        # Force address to be multiple of 4 (needed for strict alignment)
        if address % 4 != 0:
            log.warn("readMemAligned: address (0x%x) must be 4-byte aligned!" % address)
            return None

        recvQueue = Queue.Queue(1)
        def hciFilterFunction(record):
            hcipkt = record[0]
            if not issubclass(hcipkt.__class__, hci.HCI_Event):
                return False
            if hcipkt.event_code != 0xff:
                return False
            if hcipkt.data[0:4] != "READ":
                return False
            return True

        self.registerHciRecvQueue(recvQueue, hciFilterFunction)

        read_addr = address
        byte_counter = 0
        outbuffer = ''
        if bytes_total == 0:
            bytes_total = length
        while(read_addr < address+length):
            bytes_left = length - byte_counter
            blocksize = bytes_left
            if blocksize > 244:
                blocksize = 244

            # Customize the assembler snippet with the current read_addr and blocksize
            code = asm(self.fw.READ_MEM_ALIGNED_ASM_SNIPPET % (blocksize, read_addr, blocksize/4), vma=self.fw.READ_MEM_ALIGNED_ASM_LOCATION, arch='thumb')

            # Write snippet to the RAM (TODO: maybe backup and restore content of this area?)
            self.writeMem(self.fw.READ_MEM_ALIGNED_ASM_LOCATION, code)

            # Run snippet
            if not self.launchRam(self.fw.READ_MEM_ALIGNED_ASM_LOCATION):
                log.error("readMemAligned: launching assembler snippet failed!")
                return None

            # wait for the custom HCI event sent by the snippet:
            try:
                record = recvQueue.get(timeout=1)
            except Queue.Empty:
                log.warn("readMemAligned: No response from assembler snippet.")
                return None

            hcipkt = record[0]
            data = hcipkt.data[4:]
            outbuffer += data
            read_addr += len(data)
            byte_counter += len(data)
            if(progress_log != None):
                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, 
                        bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                progress_log.status(msg)

        self.unregisterHciRecvQueue(recvQueue)
        return outbuffer

    def writeMem(self, address, data, progress_log=None, bytes_done=0, bytes_total=0):
        """
        Writes the <data> to the memory space of the firmware at the given
        address.

        Optional arguments for progress logs:
        - progress_log: An instance of log.progress() which will be updated during the write.
        - bytes_done:   Number of bytes that have already been written with earlier calls to
                        writeMem() and belonging to the same transaction which is covered by progress_log.
        - bytes_total:  Total bytes that will be written within the transaction covered by progress_log.
        """

        log.debug("writeMem: writing to 0x%x" % address)
        
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
            if(response == None):
                log.warn("writeMem: Timeout while reading response, probably need to wait longer.")
                return False
            elif (response[3] != '\x00'):
                log.warn("writeMem: Got error code %x in command complete event." % response[3])
                return False
            write_addr += blocksize
            byte_counter += blocksize
            if(progress_log != None):
                msg = "sending data... %d / %d Bytes" % (bytes_done+byte_counter, bytes_total)
                progress_log.status(msg)
        return True

    def launchRam(self, address):
        """
        Executes a function at the specified address in the context of the HCI
        handler thread. The function has to comply with the calling convention.
        As the function blocks the HCI handler thread, the chip will most likely
        crash (or be resetted by Android) if the function takes too long.
        """
        

        response = self.sendHciCommand(0xfc4e, p32(address))
        if (response == None):
            log.warn("Empty HCI response during launchRam, driver crashed due to invalid code or destination")
            return False

        if(response[3] != '\x00'):
            log.warn("Got error code %x in command complete event." % response[3])
            return False
        
        # Nexus 6P Bugfix
        if ('LAUNCH_RAM_PAUSE' in dir(self.fw) and self.fw.LAUNCH_RAM_PAUSE):
            log.debug("launchRam: Bugfix, sleeping %ds" % self.fw.LAUNCH_RAM_PAUSE)
            time.sleep(self.fw.LAUNCH_RAM_PAUSE)
            
        return True

    def getPatchramState(self):
        """
        Retrieves the current state of the patchram unit. The return value
        is a tuple containing 3 lists which are indexed by the slot number:
        - target_addresses: The address which is patched by this slot (or None)
        - new_values:       The new (patch) value (or None)
        - enabled_bitmap:   1 if the slot is active, 0 if not (integer)
        """

        # Check if constants are defined in fw.py
        for const in ['PATCHRAM_TARGET_TABLE_ADDRESS', 'PATCHRAM_ENABLED_BITMAP_ADDRESS',
                      'PATCHRAM_VALUE_TABLE_ADDRESS', 'PATCHRAM_NUMBER_OF_SLOTS', 'PATCHRAM_ALIGNED']:
            if const not in dir(self.fw):
                log.warn("getPatchramState: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        slot_count      = self.fw.PATCHRAM_NUMBER_OF_SLOTS
        
        # On Nexus 5, ReadMemAligned is required, while Nexus 6P supports this memory area with ReadRAM
        if self.fw.PATCHRAM_ALIGNED:
            slot_dump       = self.readMemAligned(self.fw.PATCHRAM_ENABLED_BITMAP_ADDRESS, slot_count/4)
            table_addr_dump = self.readMemAligned(self.fw.PATCHRAM_TARGET_TABLE_ADDRESS, slot_count*4)
        else:
            slot_dump       = self.readMem(self.fw.PATCHRAM_ENABLED_BITMAP_ADDRESS, slot_count/4)
            table_addr_dump = self.readMem(self.fw.PATCHRAM_TARGET_TABLE_ADDRESS, slot_count*4)
        table_val_dump  = self.readMem(self.fw.PATCHRAM_VALUE_TABLE_ADDRESS, slot_count*4)
        
        table_addresses = []
        table_values    = []
        slot_dwords     = []
        slot_bits       = []
        for dword in range(slot_count/32):
            slot_dwords.append(slot_dump[dword*32:(dword+1)*32])
        
        for dword in slot_dwords:
            slot_bits.extend(bits(dword[::-1])[::-1])
        for i in range(slot_count):
            if slot_bits[i]:
                table_addresses.append(u32(table_addr_dump[i*4:i*4+4])<<2)
                table_values.append(table_val_dump[i*4:i*4+4])
            else:
                table_addresses.append(None)
                table_values.append(None)
        return (table_addresses, table_values, slot_bits)

    def patchRom(self, address, patch, slot=None):
        """
        Patch a 4-byte value (DWORD) inside the ROM section of the firmware
        (0x0 - 0x8FFFF) using the patchram mechanism. There are 128 available
        slots for patches and patchRom() will automatically find the next free
        slot if it is not forced through the 'slot' argument (see also
        getPatchramState()).

        address: The address at which the patch should be applied
                 (if the address is not 4-byte aligned, the patch will be splitted into two slots)
        patch:   The new value which should be placed at the address (byte string of length 4)

        Returns True on success and False on failure.
        """

        # Check if constants are defined in fw.py
        for const in ['PATCHRAM_TARGET_TABLE_ADDRESS', 'PATCHRAM_ENABLED_BITMAP_ADDRESS',
                      'PATCHRAM_VALUE_TABLE_ADDRESS', 'PATCHRAM_NUMBER_OF_SLOTS']:
            if const not in dir(self.fw):
                log.warn("patchRom: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        if len(patch) != 4:
            log.warn("patchRom: patch (%s) must be a 32-bit dword!" % patch)
            return False
        
        log.debug("patchRom: applying patch 0x%x to address 0x%x" % (u32(patch), address))

        alignment = address % 4
        if alignment != 0:
            log.debug("patchRom: Address 0x%x is not 4-byte aligned!" % address)
            if slot != None:
                log.warn("patchRom: Patch must be splitted into two slots, but fixed slot value was enforced. Do nothing!")
                return False
            log.debug("patchRom: applying patch 0x%x in two rounds" % u32(patch) )
            # read original content
            orig = self.readMem(address - alignment, 8)
            # patch the difference of the 4 bytes we want to patch within the original 8 bytes
            self.patchRom(address - alignment, orig[:alignment] + patch[:4-alignment], slot)
            self.patchRom(address - alignment + 4, patch[4-alignment:] + orig[alignment+4:], slot)
            return True

        table_addresses, table_values, table_slots = self.getPatchramState()

        # Check whether the address is already patched:
        for i in range(self.fw.PATCHRAM_NUMBER_OF_SLOTS):
            if table_addresses[i] == address:
                slot = i
                log.info("patchRom: Reusing slot for address 0x%x: %d" % (address,slot))
                # Write new value to patchram value table at 0xd0000
                self.writeMem(0xd0000 + slot*4, patch)
                return True

        if slot == None:
            # Find free slot:
            for i in range(self.fw.PATCHRAM_NUMBER_OF_SLOTS):
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
        self.writeMem(self.fw.PATCHRAM_VALUE_TABLE_ADDRESS + slot*4, patch)

        # Write address to patchram target table at 0x310000
        self.writeMem(self.fw.PATCHRAM_TARGET_TABLE_ADDRESS + slot*4, p32(address >> 2))

        # Enable patchram slot (enable bitfield starts at 0x310204)
        # (We need to enable the slot by setting a bit in a multi-dword bitfield)
        target_dword = int(slot / 32)
        table_slots[slot] = 1
        slot_dword = unbits(table_slots[target_dword*32:(target_dword+1)*32][::-1])[::-1]
        self.writeMem(self.fw.PATCHRAM_ENABLED_BITMAP_ADDRESS + target_dword*4, slot_dword)
        return True

    def disableRomPatch(self, address, slot=None):
        """
        Disable a patchram slot (see also patchRom()). The slot can either be
        specified by the target address (address that was patched) or by providing
        the slot number directly (the address will be ignored in this case).

        Returns True on success and False on failure.
        """

        # Check if constants are defined in fw.py
        for const in ['PATCHRAM_TARGET_TABLE_ADDRESS', 'PATCHRAM_ENABLED_BITMAP_ADDRESS']:
            if const not in dir(self.fw):
                log.warn("disableRomPatch: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

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
        slot_dword = unbits(table_slots[target_dword*32:(target_dword+1)*32][::-1])[::-1]
        self.writeMem(self.fw.PATCHRAM_ENABLED_BITMAP_ADDRESS + target_dword*4, slot_dword)

        # Write 0xFFFFC to patchram target table at 0x310000
        # (0xFFFFC seems to be the default value if the slot is inactive)
        self.writeMem(self.fw.PATCHRAM_TARGET_TABLE_ADDRESS + slot*4, p32(0xFFFFC>>2))
        return True

    def readConnectionInformation(self, conn_number):
        """
        Reads and parses a connection struct based on the connection number.
        Note: The connection number is different from the connection index!
        The connection number starts counting at 1 and is stored in the first
        field of the connection structure.
        The connection index starts at 0 and is the index into the connection
        table (table containing all connection structs).
        In the Nexus 5 firmware all connection numbers are simply the connection
        index increased by 1.

        The return value is a dictionary containing all information that could
        be parsed from the connection structure. If the connection struct at the
        specified connection number is empty, the return value is None.
        """

        # Check if constants are defined in fw.py
        # Do we have an array implementation?
        is_array = True
        for const in ['CONNECTION_MAX', 'CONNECTION_ARRAY_ADDRESS', 'CONNECTION_STRUCT_LENGTH']:
            if const not in dir(self.fw):
                is_array = False
                
                # Do we have a list implementation?
                for const in ['CONNECTION_LIST_ADDRESS']:
                    if const not in dir(self.fw):
                        log.warn("readConnectionInformation: neither CONNECTION_LIST nor CONNECTION_ARRAY in fw.py. FEATURE NOT SUPPORTED!")
                        return None

        if conn_number < 1 or conn_number > self.fw.CONNECTION_MAX:
            log.warn("readConnectionInformation: connection number out of bounds: %d" % conn_number)
            return None

        if is_array:
            connection = self.readMem(self.fw.CONNECTION_ARRAY_ADDRESS +
                            self.fw.CONNECTION_STRUCT_LENGTH*(conn_number-1),
                            self.fw.CONNECTION_STRUCT_LENGTH)
        else:
            connection_memaddr = u32(self.readMem(self.fw.CONNECTION_LIST_ADDRESS + 4*(conn_number-1), 4))
            if (connection_memaddr == 0x00000000):
                return None
            connection = self.readMem(connection_memaddr, self.fw.CONNECTION_STRUCT_LENGTH)

        if connection == b'\x00'*self.fw.CONNECTION_STRUCT_LENGTH:
            return None

        conn_dict = {}
        conn_dict["connection_number"]    = u32(connection[:4])
        conn_dict["remote_address"]       = connection[0x28:0x2E][::-1]
        conn_dict["remote_name_address"]  = u32(connection[0x4C:0x50])
        conn_dict["master_of_connection"] = u32(connection[0x1C:0x20]) & 1<<15 == 0
        conn_dict["connection_handle"]    = u16(connection[0x64:0x66])
        conn_dict["public_rand"]          = connection[0x78:0x88]
        #conn_dict["pin"]                  = connection[0x8C:0x92]
        #conn_dict["bt_addr_for_key"]      = connection[0x92:0x98][::-1]
        effective_key_len                 = u8(connection[0xa7:0xa8])
        conn_dict["effective_key_len"]    = effective_key_len
        conn_dict["link_key"]             = connection[0x68:0x68+effective_key_len]
        #new fields - TODO verify
        conn_dict["tx_pwr_lvl_dBm"]       = u8(connection[0x9c:0x9d]) - 127
        conn_dict["extended_lmp_feat"]    = connection[0x30:0x38] #standard p. 527
        conn_dict["host_supported_feat"]  = connection[0x38:0x40]
        conn_dict["id"]                   = connection[0x0c:0x0d] #not sure if this is an id?
        return conn_dict

    def sendLmpPacket(self, opcode, payload, is_master=True, conn_handle=0x0c, extended_op=False):
        """
        Inject a LMP packet into a Bluetooth connection (i.e. send a LMP packet
        to a remote device which is paired and connected with our local device).
        This code is using the vendor specific HCI command 0xfc58, which sends
        an LMP PDU. Note that Broadcom firmware internally checks opcodes and 
        lengths, meaning that despite returning success long payloads will be
        cut and invalid opcodes might be discarded.

        is_master:   Determines if we are master or slave within the connection.
        conn_handle: The connection handle specifying the connection into which the
                     packet will be injected. By default, the first connection handle
                     used by Broadcom is 0x0c.
        opcode:      The LMP opcode of the LMP packet that will be injected.
        payload:     The LMP payload of the LMP packet that will be injected.
                     Can be empty.
        extended_op: Set to True if the opcode should be interpreted as extended / escaped
                     LMP opcode.

        Returns True on success and False on failure.
        """
        
        # Check the connection handle
        # Range: 0x0000-0x0EFF (all other values reserved for future use)
        if conn_handle < 0 or conn_handle > 0x0EFF:
            log.warn("sendLmpPacket: connection handle out of bounds: %d" % conn_handle)
            return False
        
        # must be string...
        if payload == None:
            payload = ''
        
        # Build the LMP packet
        # (The TID bit will later be set in the assembler code)
        opcode_data = p8(opcode<<1 | (not is_master)) if not extended_op else p8(0x7F<<1 | (not is_master)) + p8(opcode)
        data = opcode_data + payload
        
        #log.info("packet: " + p16(conn_handle) + p8(len(data)) + data)
        result = self.sendHciCommand(0xfc58, p16(conn_handle) + p8(len(data)) + data)
        result = u8(result[3])
        
        if (result != 0):
            log.warn("sendLmpPacket: got error status 0x%02x" % result)
            return False
        
        return True
    
    def sendLmpPacketLegacy(self, conn_nr, opcode, payload, extended_op=False):
        """
        Inject a LMP packet into a Bluetooth connection (i.e. send a LMP packet
        to a remote device which is paired and connected with our local device).
        This is legacy code only running on BCM4339 based on assembly patches.

        conn_nr:     The connection number specifying the connection into which the
                     packet will be injected.
        opcode:      The LMP opcode of the LMP packet that will be injected.
        payload:     The LMP payload of the LMP packet that will be injected.
                     Note: The size of the payload is defined by its opcode.
                     TODO: Go one step deeper in order to send arbitrary length
                     LMP packets.
        extended_op: Set to True if the opcode should be interpreted as extended / escaped
                     LMP opcode.

        Returns True on success and False on failure.
        """

        # Check if constants are defined in fw.py
        for const in ['CONNECTION_MAX', 'SENDLMP_CODE_BASE_ADDRESS', 'SENDLMP_ASM_CODE']:
            if const not in dir(self.fw):
                log.warn("sendLmpPacket: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        # connection number bounds check
        if conn_nr < 1 or conn_nr > self.fw.CONNECTION_MAX:
            log.warn("sendLmpPacket: connection number out of bounds: %d" % conn_nr)
            return False

        # Build the LMP packet
        # (The TID bit will later be set in the assembler code)
        opcode_data = p8(opcode<<1) if not extended_op else p8(0x7F<<1) + p8(opcode)
        data = opcode_data + payload

        # Prepare the assembler snippet by injecting the connection number
        # and appending the LMP packet data.
        asm_code = self.fw.SENDLMP_ASM_CODE % (conn_nr)
        asm_code_with_data = asm_code + ''.join([".byte 0x%02x\n" % ord(x) 
                for x in data.ljust(20, "\x00")])

        # Assemble the snippet and write it to SENDLMP_CODE_BASE_ADDRESS
        code = asm(asm_code_with_data, vma=self.fw.SENDLMP_CODE_BASE_ADDRESS, arch='thumb')
        self.writeMem(self.fw.SENDLMP_CODE_BASE_ADDRESS, code)

        # Invoke the snippet
        if self.launchRam(self.fw.SENDLMP_CODE_BASE_ADDRESS):
            return True
        else:
            log.warn("sendLmpPacket: launchRam failed!")
            return False

    def connectToRemoteDevice(self, bt_addr):
        """
        Send a HCI Connect Command to the firmware. This will setup
        a connection (inserted into the connection structure) if the
        remote device (specified by bt_addr) accepts.
        To be exact: This will most likely send
        - LMP_features_req
        - LMP_version_req
        - LMP_features_req_ext
        - LMP_host_connection_req
        - LMP_setup_complete
        and also other channel-related packets to the remote device.
        The devices do not have to be paired and the remote device
        does not need to be visible. This will not initiate the
        pairing sequence, therefore the remote host will not show
        any notification to the user yet, the host is however notified
        via HCI that there is an incomming connection.
        
        bt_addr:  address of remote device (byte string)
                  e.g. for 'f8:95:c7:83:f8:11' you would pass
                  b'\xf8\x95\xc7\x83\xf8\x11'.
        """

        # TODO: expose more of the connection create parameters (instead of
        #       passing 0's.
        self.sendHciCommand(0x0405, bt_addr[::-1] + '\x00\x00\x00\x00\x00\x00\x01')

    def connectionStatusCallback(self, record):
        """
        HCI Callback function to detect HCI Events related to
        Create Connection
        """

        hcipkt    = record[0]   # get HCI Event packet
        timestamp = record[5]   # get timestamp

        if not issubclass(hcipkt.__class__, hci.HCI_Event):
            return

        # Check if event is Connection Create Status Event
        if hcipkt.event_code == 0x0f:
            if u16(hcipkt.data[2:4]) == 0x0405: # Create Connection HCI Cmd
                log.info("[Connection Create initiated]")
                return

        # Check if event is Connection Create Complete Event
        if hcipkt.event_code == 0x03:
            status      = u8(hcipkt.data[0])
            status_str  = hex(status) if status not in hcipkt.HCI_COMMAND_ERROR_STR else hcipkt.HCI_COMMAND_ERROR_STR[status]
            conn_handle = u16(hcipkt.data[1:3])
            btaddr      = hcipkt.data[3:9][::-1]
            btaddr_str  = ":".join([b.encode("hex") for b in btaddr])
            log.info("[Connect Complete: Handle=0x%x  Address=%s  status=%s]" % (conn_handle, btaddr_str, status_str))


    def readHeapInformation(self):
        """
        Traverses the double-linked list of BLOC structs and returns them as a
        list of dictionaries. The dicts have the following fields:
        - index:            Index of the BLOC struct inside the double-linked list
        - address:          Address of the BLOC struct
        - list_length:      Number of available buffers currently in the list
        - capacity:         Total number of buffers belonging to the struct
        - buffer_list:      Head of the buffer list (single-linked list)
        - memory:           Address of the backing buffer in memory
        - memory_size:      Size of the backing buffer in memory
        - buffer_size:      Size of a single buffer in the list
        - thread_waitlist:  Head of the list of threads, that wait for a buffer to become available
        - waitlist_length:  Length of the waiting list
        - prev:             Previous BLOC struct (double-linked list)
        - next:             Next BLOC struct (double-linked list)
        """

        # Check if constants are defined in fw.py
        for const in ['BLOC_HEAD']:
            if const not in dir(self.fw):
                log.warn("readHeapInformation: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        # Read address of first bloc struct:
        first_bloc_struct_address = u32(self.readMem(self.fw.BLOC_HEAD, 4))

        # Traverse the double-linked list
        bloclist = []
        current_bloc_struct_address = first_bloc_struct_address
        for index in range(100): # Traverse at most 100 (don't loop forever if linked-list is corrupted)
            bloc_struct = self.readMem(current_bloc_struct_address, 0x30)
            bloc_fields = struct.unpack("I"*12, bloc_struct)
            if bloc_fields[0] != u32("COLB"):
                log.warn("readHeapInformation: BLOC double-linked list contains non-BLOC element. abort.")
                return None
            current_element = {}
            current_element["index"]           = index
            current_element["address"]         = current_bloc_struct_address
            current_element["list_length"]     = bloc_fields[2]
            current_element["capacity"]        = bloc_fields[3]
            current_element["buffer_list"]     = bloc_fields[4]
            current_element["memory"]          = bloc_fields[5]
            current_element["memory_size"]     = bloc_fields[6]
            current_element["buffer_size"]     = bloc_fields[7]
            current_element["thread_waitlist"] = bloc_fields[8]
            current_element["waitlist_length"] = bloc_fields[9]
            current_element["next"]            = bloc_fields[10]
            current_element["prev"]            = bloc_fields[11]
            bloclist.append(current_element)

            current_bloc_struct_address = current_element["next"]
            if current_bloc_struct_address == first_bloc_struct_address:
                break
        return bloclist

    def readQueueInformation(self):
        """
        Traverses the double-linked list of QUEUE structs and returns them as a
        list of dictionaries. The dicts have the following fields:
        - index:            Index of the BLOC struct inside the double-linked list
        - address:          Address of the BLOC struct
        - item_size:        Size of a single queue item (in Byte)
        - capacity:         Total number of queue items belonging to the struct
        - available_items:  Number of valid queue items ready to be retrieved
        - free_slots:       Number of free item slots
        - queue_buf_start:  Pointer to the beginning of the queue buffer
        - queue_buf_end:    Pointer to the end of the queue buffer
        - next_item:        Pointer to the next item to be retrieved from the queue
        - next_free_slot:   Pointer to the next free item slot to be filled
        - thread_waitlist:  Head of the list of threads, that wait for a buffer to become available
        - waitlist_length:  Length of the waiting list
        - prev:             Previous BLOC struct (double-linked list)
        - next:             Next BLOC struct (double-linked list)
        - items:            List of queue items (raw bytes)
        - name:             Name of the queue (from reverse engineering its usage)
        """

        # Check if constants are defined in fw.py
        for const in ['QUEUE_HEAD']:
            if const not in dir(self.fw):
                log.warn("readQueueInformation: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        # Read address of first queue struct:
        first_queue_struct_address = u32(self.readMem(self.fw.QUEUE_HEAD, 4))

        # Traverse the double-linked list
        queuelist = []
        current_queue_struct_address = first_queue_struct_address
        for index in range(100): # Traverse at most 100 (don't loop forever if linked-list is corrupted)
            queue_struct = self.readMem(current_queue_struct_address, 0x38)
            queue_fields = struct.unpack("I"*14, queue_struct)
            if queue_fields[0] != u32("UEUQ"):
                log.warn("readQueueInformation: QUEUE double-linked list contains non-QUEU element. abort.")
                return None
            current_element = {}
            current_element["index"]           = index
            current_element["address"]         = current_queue_struct_address
            current_element["item_size"]       = queue_fields[2] * 4 # Item size is measured in dwords (4 Byte)
            current_element["capacity"]        = queue_fields[3]
            current_element["available_items"] = queue_fields[4]
            current_element["free_slots"]      = queue_fields[5]
            current_element["queue_buf_start"] = queue_fields[6]
            current_element["queue_buf_end"]   = queue_fields[7]
            current_element["next_item"]       = queue_fields[8]
            current_element["next_free_slot"]  = queue_fields[9]
            current_element["thread_waitlist"] = queue_fields[10]
            current_element["waitlist_length"] = queue_fields[11]
            current_element["next"]            = queue_fields[12]
            current_element["prev"]            = queue_fields[13]
            current_element["name"]            = self.fw.QUEUE_NAMES[index]
            queuelist.append(current_element)

            current_queue_struct_address = current_element["next"]
            if current_queue_struct_address == first_queue_struct_address:
                break
        return queuelist

