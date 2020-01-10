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
from .fw.fw import Firmware
import datetime
import time
import Queue
from . import hci

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple, Union, NewType, Callable
    from internalblue import Address, Record, Task, HCI_CMD, FilterFunction, ConnectionNumber, ConnectionDict, \
    ConnectionIndex, BluetoothAddress, HeapInformation, QueueInformation, Opcode
    from internalblue.hci import HCI
    from . import DeviceTuple
    if TYPE_CHECKING:
        pass
except:
    pass

import logging
log = logging.getLogger(__name__)

class InternalBlue:
    __metaclass__ = ABCMeta

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        # type: (int, str, str, bool, str) -> None
        context.log_level = log_level
        context.log_file = data_directory + '/_internalblue.log'
        context.arch = "thumb"

        self.interface = None   # holds the context.device / hci interaface which is used to connect, is set in cli
        self.fw = None          # holds the firmware file


        self.data_directory = data_directory
        self.s_inject = None    #type: socket.socket # This is the TCP socket to the HCI inject port
        self.s_snoop = None     #type: socket.socket  # This is the TCP socket to the HCI snoop port

        # If btsnooplog_filename is set, write all incomming HCI packets to a file (can be viewed in wireshark for debugging)
        if btsnooplog_filename is not None:
            self.write_btsnooplog = True
            self.btsnooplog_file = open(self.data_directory + "/" + btsnooplog_filename, "wb")
        else:
            self.write_btsnooplog = False

        # The sendQueue connects the core framework to the sendThread. With the
        # function sendH4 or sendHciCommand, the core framework (or a CLI command / user script)
        # can put an H4 packet or HCI Command into this queue. The queue entry should be a tuple:
        # (h4type, data, response_queue, response_hci_filter_function)
        #   - h4type: The H4 packet type (e.g. 1 for HCI Command or 7 for Broadcom Diagnostic)
        #   - data:   The H4 payload (byte string)
        #   - response_queue: queue that is used for delivering the H4 response
        #                     back to the entity that put the H4 command into the
        #                     sendQueue. May be None if no response is expected/needed.
        #                     If a response_queue is specified, it is also necessary to
        #                     specify a response_hci_filter_function.
        #   - response_hci_filter_function: An hci callback function (see registerHciCallback())
        #                     that is used to test whether incomming H4 packets are the
        #                     response to the packet that was sent. May be None if response_queue
        #                     is also None.
        # The sendThread polls the queue, gets the above mentioned tuple, sends the
        # H4 command to the firmware and then waits for the response from the
        # firmware (the response is recognized with the help of the filter function).
        # Once the response arrived, it puts the response into the response_queue from
        # the tuple. See sendH4() and sendHciCommand().
        self.sendQueue = Queue.Queue(queue_size) # type: Queue.Queue[Task]

        self.recvThread = None                  # The thread which is responsible for the HCI snoop socket
        self.sendThread = None                  # The thread which is responsible for the HCI inject socket

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
        self.registeredHciRecvQueues = [] # type: List[Tuple[Queue.Queue[Record], FilterFunction]]

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
        self.registerHciCallback(self.coexStatusCallback)

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

    def _parse_time(self, time):
        # type: (Any) -> datetime.datetime
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
    
    @abstractmethod
    def _recvThreadFunc(self):
        # type: () -> None
        pass

    def _sendThreadFunc(self):
        # type: () -> None
        """
        This is the run-function of the sendThread. It polls the sendQueue for new 'send tasks'
        and executes them (sends H4 commands to the chip and returns the response).
        The entries of the sendQueue are tuples representing a 'send task':
         (h4type, payload, response_queue)
           - h4type: The H4 type (8 bit integer) to send
           - data:   The H4 payload (byte string) to send
           - response_queue: queue that is used for delivering the H4 response
                             back to the entity that put the H4 command into the
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

            # Extract the components of the task
            try:
                h4type, data, queue, filter_function = task
            except ValueError:
                # might happen if H4 is not supported
                log.debug("Failed to unpack queue item.")
                continue

            # Special handling of ADBCore and HCICore
            # ADBCore: adb transport requires to prepend the H4 data with its length
            # HCICore: need to manually save the data to btsnoop log as it is not
            #          reflected to us as with adb
            if   self.__class__.__name__ == "ADBCore":
                # prepend with total length for H4 over adb with modified Bluetooth module
                if not self.serial:
                    data = p16(len(data)) + data

                # If we do not have a patched module, we write to the serial using the same socket.
                # Echoing HCI commands to the serial interface has the following syntax:
                #
                #   echo -ne "\x01\x4c\xfc\x05\x33\x22\x11\x00\xaa"
                #   0x01:       HCI command
                #   0xfc4c:     Write RAM
                #   0x05:       Parameter length
                #   0x3322...:  Parameters
                #
                # ...and that's how the data is formatted already anyway

            elif self.__class__.__name__ == "HCICore":
                if self.write_btsnooplog:
                    # btsnoop record header data:
                    btsnoop_data     = p8(h4type) + data
                    btsnoop_orig_len = len(btsnoop_data)
                    btsnoop_inc_len  = len(btsnoop_data)
                    btsnoop_flags    = 0
                    btsnoop_drops    = 0
                    btsnoop_time     = datetime.datetime.now()
                    btsnoop_record_hdr = struct.pack(">IIIIq", btsnoop_orig_len, btsnoop_inc_len, btsnoop_flags,
                                                        btsnoop_drops, self._btsnoop_pack_time(btsnoop_time))
                    with self.btsnooplog_file_lock:
                        self.btsnooplog_file.write(btsnoop_record_hdr)
                        self.btsnooplog_file.write(btsnoop_data)
                        self.btsnooplog_file.flush()

            # Prepend UART TYPE and length.
            out = p8(h4type) + data

            # if the caller expects a response: register a queue to receive the response
            if queue != None and filter_function != None:
                recvQueue = Queue.Queue(1)
                self.registerHciRecvQueue(recvQueue, filter_function)

            # Send command to the chip using s_inject socket
            try:
                log.debug("_sendThreadFunc: Send: " + str(out.encode('hex')))
                self.s_inject.send(out)
            except:
                log.warn("_sendThreadFunc: Sending to socket failed, reestablishing connection.\nWith HCI sockets, some HCI commands require root!")
                # socket are terminated by hcicore..
                self._teardownSockets()
                self._setupSockets()

            # if the caller expects a response:
            # Wait for the HCI event response by polling the recvQueue
            if queue != None and filter_function != None:
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

    def _tracepointHciCallbackFunction(self, record):
        # type: (Record) -> None
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
        # type: (Address) -> bool
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
        self.disableRomPatch(address)  # Eval board requires to delete patch before installing it again

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
        # type: (Address) -> bool
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
        # type: () -> bool
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
        # type: () -> List[DeviceTuple]
        pass

    def connect(self):
        # type: () -> bool
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
        
        if not self.initialize_fimware():
            log.warn("connect: Failed to initialize firmware!")
            return False

        self.running = True

        return True

    @abstractmethod
    def local_connect(self):
        return True
    
    def initialize_fimware(self):
        # type: () -> bool
        """
        Checks if we are running on a Broadcom chip and loads available firmware information based
        on LMP subversion.
        """

        # send Read_Local_Version_Information
        version = self.sendHciCommand(0x1001, '')
        
        if not version or len(version) < 11:
            log.warn("""initialize_fimware: Failed to send a HCI command to the Bluetooth driver.
            adb: Check if you installed a custom bluetooth.default.so properly on your
              Android device. bluetooth.default.so must contain the string 'hci_inject'.
            hci: You might have insufficient permissions to send this type of command.""")
            return False

        # Broadcom uses 0x000f as vendor ID, Cypress 0x0131
        vendor = (u8(version[9]) << 8) + u8(version[8])
        if vendor != 0xf and vendor != 0x131:
            log.critical("Not running on a Broadcom or Cypress chip!")
            return False
        else:
            subversion = (u8(version[11]) << 8) + u8(version[10])

            iOS = False
            if self.__class__.__name__ == "iOSCore":
                iOS = True

            self.fw = Firmware(subversion, iOS).firmware
        
        # Safe to turn diagnostic logging on, it just gets a timeout if the Android
        # driver was recompiled with other flags but without applying a proper patch.
        log.info("Try to enable debugging on H4 (warning if not supported)...")
        self.enableBroadcomDiagnosticLogging(True)
            
        return True

    def shutdown(self):
        # type: () -> None
        """
        Shutdown the framework by stopping the send and recv threads. Socket shutdown
        also terminates port forwarding if adb is used.
        """

        # Setting exit_requested to True will stop the send and recv threads at their
        # next while loop iteration
        self.exit_requested = True

        # unregister stackDumpReceiver callback:
        if self.stackDumpReceiver != None:
            self.stackDumpReceiver = None

        # unregister stackDumpReceiver callback:
        if self.stackDumpReceiver != None:
            self.unregisterHciCallback(self.stackDumpReceiver.recvPacket)

        # Wait until both threads have actually finished
        self.recvThread.join()
        self.sendThread.join()

        # Disconnect the TCP sockets
        self._teardownSockets()

        if (self.write_btsnooplog):
            self.btsnooplog_file.close()

        self.running = False
        self.exit_requested = False
        log.info("Shutdown complete.")

    def registerHciCallback(self, callback):
        # type: (Callable[[Record], None ]) -> None
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
        # type: (Callable[[Tuple[HCI, int, int, int, Any, datetime.datetime]], None ]) -> None
        """
        Remove a callback function from self.registeredHciCallbacks.
        """

        if callback in self.registeredHciCallbacks:
            self.registeredHciCallbacks.remove(callback)
            return
        log.warn("registerHciCallback: no such callback is registered!")

    def registerHciRecvQueue(self, queue, filter_function=None):
        # type: (Queue.Queue[Record], FilterFunction) -> None
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
        # type: (Queue.Queue[Tuple[HCI, int, int, int, Any, datetime]]) -> None
        """
        Remove a queue from self.registeredHciRecvQueues.
        """

        for entry in self.registeredHciRecvQueues:
            if entry[0] == queue:
                self.registeredHciRecvQueues.remove(entry)
                return
        log.warn("registerHciRecvQueue: no such queue is registered!")

    def sendHciCommand(self, opcode, data, timeout=3):
        # type: (Opcode, bytes, int) -> Optional[Any]
        """
        Send an arbitrary HCI command packet by pushing a send-task into the
        sendQueue. This function blocks until the response is received
        or the timeout expires. The return value is the Payload of the
        HCI Command Complete Event which was received in response to
        the command or None if no response was received within the timeout.
        """
        #TODO: If the response is a HCI Command Status Event, we will actually
        #      return this instead of the Command Complete Event (which will
        #      follow later and will be ignored). This should be fixed..

        queue = Queue.Queue(1)

        # standard HCI command structure
        payload = p16(opcode) + p8(len(data)) + data

        # define a filter function which recognizes the response (command complete
        # or command status event).
        def recvFilterFunction(record):
            # type: (Record) -> bool
            hcipkt = record[0]

            log.debug("sendHciCommand.recvFilterFunction: got response")

            # Interpret HCI event
            if isinstance(hcipkt, hci.HCI_Event):
                if hcipkt.event_code == 0x0e:   # Cmd Complete event
                    if u16(hcipkt.data[1:3]) == opcode:
                        return True

                if hcipkt.event_code == 0x0f:   # Cmd Status event
                    if u16(hcipkt.data[2:4]) == opcode:
                        return True

            return False

        try:
            self.sendQueue.put((hci.HCI.HCI_CMD, payload, queue, recvFilterFunction),
                               timeout=timeout)
            ret = queue.get(timeout=timeout)
            return ret
        except Queue.Empty:
            log.warn("sendHciCommand: waiting for response timed out!")
            return None
        except Queue.Full:
            log.warn("sendHciCommand: send queue is full!")
            return None

    def sendH4(self, h4type, data, timeout=2):
        # type: (HCI_CMD, bytes, int) -> bool
        """
        Send an arbitrary H4 packet by pushing a send-task into the
        sendQueue. This function does not wait for a response! If you
        need to receive a response, register an hciRecvQueue or -callback.
        The return value is True if the send-task could be put inside the
        queue and False if it was not possible within the timeout.
        """

        try:
            self.sendQueue.put((h4type, data, None, None), timeout=timeout)
            return True
        except Queue.Full:
            log.warn("sendH4: send queue is full!")
            return False

    def recvPacket(self, timeout=None):
        # type: (Optional[int]) -> Optional[Record]
        """
        This function polls the recvQueue for the next available HCI
        packet and returns it. The function checks whether it is called
        from the sendThread or any other thread and respectively chooses
        either the sendThreadrecvQueue or the recvQueue. (FIXME: no it does not?!)

        The recvQueue is filled by the recvThread. If the queue fills up
        the recvThread empties the queue (unprocessed packets are lost).
        The recvPacket function is meant to receive raw HCI packets in
        a blocking manner. Consider using the registerHciCallback()
        functionality as an alternative which works asynchronously.
        """
        
        log.debug("recvPacket: called")

        if not self.check_running():
            return None

        try:
            return self.recvQueue.get(timeout=timeout)
        except Queue.Empty:
            return None

    def readMem(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        # type: (int, int, Optional[Any], int, int) -> Optional[bytes]
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
        retry = 3                   # Retry on failures
        while read_addr < address+length:  # Send HCI Read_RAM commands until all data is received
            # Send hci frame
            bytes_left = length - byte_counter
            blocksize = bytes_left
            if blocksize > 251:     # The max. size of a Read_RAM payload is 251
                blocksize = 251

            # Send Read_RAM (0xfc4d) command
            response = self.sendHciCommand(0xfc4d, p32(read_addr) + p8(blocksize))

            if response is None or not response:
                log.warn("readMem: No response to readRAM HCI command! (read_addr=%x, len=%x)" % (read_addr, length))
                # Retry once...
                if retry > 0:
                    log.debug("readMem: retrying once...")
                    retry = retry - 1
                    continue
                else:
                    log.warning("readMem: failed!")
                    return None

            data = response[4:]  # start of the actual data is at offset 4

            if len(data) == 0:  # this happens i.e. if not called on a brcm chip
                log.warn("readMem: empty response, quitting...")
                break

            if len(data) != blocksize:
                log.debug("readMem: insufficient bytes returned, retrying...")
                continue

            status = ord(response[3])
            if status != 0:
                # It is not yet reverse engineered what this byte means. For almost
                # all memory addresses it will be 0. But for some it will be different,
                # EDIT: response should be a command complete event (event code 0x0e). The 4 byte (response[3]) indicates the hci error code
                #       0x00 (0) means everything okay
                #       0x12 means Command Disallowed
                # e.g. for address 0xff000000 (aka 'EEPROM') it is 0x12
                log.warn("readMem: [TODO] Got status != 0 : error 0x%02X at address 0x%08x" % (status, read_addr))
                break

            # do double checking, but prevent loop
            if self.doublecheck and retry > 0:
                response_check = self.sendHciCommand(0xfc4d, p32(read_addr) + p8(blocksize))
                if response != response_check:
                    log.debug("readMem: double checking response failed at 0x%x! retry..." % read_addr)
                    sleep(0.3)
                    retry = retry - 1
                    continue

            outbuffer += data
            read_addr += len(data)
            byte_counter += len(data)
            if(progress_log != None):
                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, 
                        bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                progress_log.status(msg)
            retry = 3  # this round worked, so we re-enable retries
        return outbuffer

    def readMemAligned(self, address, length, progress_log=None, bytes_done=0, bytes_total=0):
        # type: (int, int, Optional[Any], int, int) -> Any
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
            # type: (Record) -> bool
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
                # on iOSCore the return value might be wrong
                if self.doublecheck:
                    log.debug("readMemAligned: probably failed, but continuing...")
                else:
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
            if progress_log is not None:
                msg = "receiving data... %d / %d Bytes (%d%%)" % (bytes_done+byte_counter, 
                        bytes_total, (bytes_done+byte_counter)*100/bytes_total)
                progress_log.status(msg)

        self.unregisterHciRecvQueue(recvQueue)
        return outbuffer

    def writeMem(self, address, data, progress_log=None, bytes_done=0, bytes_total=0):
        # type: (int, bytes, Optional[Any], int, int) -> Optional[bool]
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
                log.warn("writeMem: Got error code %s in command complete event." % response[3].encode('hex'))
                return False
            write_addr += blocksize
            byte_counter += blocksize
            if(progress_log != None):
                msg = "sending data... %d / %d Bytes" % (bytes_done+byte_counter, bytes_total)
                progress_log.status(msg)
        return True

    def launchRam(self, address):
        # type: (int) -> bool
        """
        Executes a function at the specified address in the context of the HCI
        handler thread. The function has to comply with the calling convention.
        As the function blocks the HCI handler thread, the chip will most likely
        crash (or be resetted by Android) if the function takes too long.
        """

        response = self.sendHciCommand(0xfc4e, p32(address))
        if response is None:
            log.warn("Empty HCI response during launchRam, driver crashed due to invalid code or destination")
            return False

        if response[3] != '\x00':
            log.warn("Got error code %x in command complete event." % u8(response[3]))
            return False
        
        # Nexus 6P Bugfix
        if 'LAUNCH_RAM_PAUSE' in dir(self.fw) and self.fw.LAUNCH_RAM_PAUSE:
            log.debug("launchRam: Bugfix, sleeping %ds" % self.fw.LAUNCH_RAM_PAUSE)
            time.sleep(self.fw.LAUNCH_RAM_PAUSE)
            
        return True

    def getPatchramState(self):
        # type: () -> Tuple[List[Optional[int]], List[Any], List[Any]]
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
        # type: (int, Any, Optional[Any]) -> bool
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
                self.writeMem(self.fw.PATCHRAM_VALUE_TABLE_ADDRESS + slot*4, patch)
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
        # type: (int, Optional[int]) -> bool
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
            for i in range(self.fw.PATCHRAM_NUMBER_OF_SLOTS):
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
        # type: (ConnectionNumber) -> Optional[ConnectionDict]
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

    def sendLmpPacket(self, opcode, payload='', is_master=True, conn_handle=0x0c, extended_op=False):
        # type: (Opcode, Any, bool, ConnectionNumber, bool) -> bool
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
        
        if ((not extended_op) and opcode > (0xff>>1)) or (extended_op and opcode > 0xff):
            log.warn("sendLmpPacket: opcode out of range!")
            return False
        
        # Build the LMP packet
        opcode_data = p8(opcode<<1 | (not is_master)) if not extended_op else p8(0x7F<<1 | (not is_master)) + p8(opcode)
        
        # Nexus 5 (2012) simply takes any length as argument, but later withdraws bytes if too many were passed.
        # Nexus 6P, Raspi 3+ and evaulation board (2014-2018) require a fixed 20 byte length parameter to be passed!
        #   -> 2 bytes connection handle, 1 byte length, which means 17 bytes for opcode and payload remaining
        #   sendlmp --data 11223344556677889900112233445566 01 -> actually works
        #   always pad to 17 data bytes...
        data = opcode_data + payload + '\x00'*(17 - len(opcode_data) - len(payload))
        
        if len(data) > 17:
            log.warn("sendLmpPacket: Vendor specific HCI command only allows for 17 bytes LMP content.")
        
        #log.info("packet: " + p16(conn_handle) + p8(len(data)) + data)
        result = self.sendHciCommand(0xfc58, p16(conn_handle) + p8(len(payload + opcode_data)) + data)
        
        if result == None:
            log.warn("sendLmpPacket: did not get a result from firmware, maybe crashed internally?")
            return False
        
        result = u8(result[3])
        
        if result != 0:
            log.warn("sendLmpPacket: got error status 0x%02x" % result)
            return False
        
        return True

    def fuzzLmp(self):
        # type: ()-> bool
        """
        Installs a patch inside the sendLmp HCI handler that allows sending arbitrary
        LMP payloads. Afterwards, use sendLmpPacket as before.

        Basically, this ignores LM_LmpInfoTable and LM_LmpInfoTableEsc4 contents, but
        only via sendLmp HCI and not during normal Link Manager operation.
        """

        # Check if constants are defined in fw.py
        for const in ['FUZZLMP_CODE_BASE_ADDRESS', 'FUZZLMP_ASM_CODE', 'FUZZLMP_HOOK_ADDRESS']:
            if const not in dir(self.fw):
                log.warn("fuzzLmpPacket: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        # Assemble the snippet and write it to FUZZLMP_CODE_BASE_ADDRESS
        code = asm(self.fw.FUZZLMP_ASM_CODE, vma=self.fw.FUZZLMP_CODE_BASE_ADDRESS, arch='thumb')
        self.writeMem(self.fw.FUZZLMP_CODE_BASE_ADDRESS, code)

        # Install a patch in the end of the original sendLmpPdu HCI handler
        patch = asm("b 0x%x" % self.fw.FUZZLMP_CODE_BASE_ADDRESS, vma=self.fw.FUZZLMP_HOOK_ADDRESS)
        if not self.patchRom(self.fw.FUZZLMP_HOOK_ADDRESS, patch):
            log.warn("Error writing to patchram when installing fuzzLmp patch!")
            return False

        return True

    def sendLmpPacketLegacy(self, conn_nr, opcode, payload, extended_op=False):
        # type: (int, Opcode, bytes, bool) -> bool
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
        asm_code = self.fw.SENDLMP_ASM_CODE % (conn_nr) # type: str
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

    def sendLcpPacket(self, conn_idx, payload):
        # type: (ConnectionIndex, bytes) -> bool
        """
        Inject a LCP packet into a Bluetooth LE connection (i.e. send a LCP packet
        to a remote device which is paired and connected with our local device).
        This is code requires assembly patches.

        conn_idx:     The connection index specifying the connection into which the
                     packet will be injected, starting at 0.
        payload:     The LCP opcode and payload of the LCP packet that will be injected.

        Returns True on success and False on failure.
        """

        # Check if constants are defined in fw.py
        for const in ['SENDLCP_CODE_BASE_ADDRESS', 'SENDLCP_ASM_CODE']:
            if const not in dir(self.fw):
                log.warn("sendLcpPacket: '%s' not in fw.py. FEATURE NOT SUPPORTED!" % const)
                return False

        # Prepare the assembler snippet by injecting the connection number
        # and appending the LMP packet data.
        asm_code = self.fw.SENDLCP_ASM_CODE % (conn_idx, len(payload))
        asm_code_with_data = asm_code + ''.join([".byte 0x%02x\n" % ord(x)
                for x in payload.ljust(20, "\x00")])

        # Assemble the snippet and write it to SENDLCP_CODE_BASE_ADDRESS
        code = asm(asm_code_with_data, vma=self.fw.SENDLCP_CODE_BASE_ADDRESS, arch='thumb')
        self.writeMem(self.fw.SENDLCP_CODE_BASE_ADDRESS, code)

        # Invoke the snippet
        if self.launchRam(self.fw.SENDLCP_CODE_BASE_ADDRESS):
            return True
        else:
            log.warn("sendLcpPacket: launchRam failed!")
            return False

    def connectToRemoteDevice(self, bt_addr):
        # type: (BluetoothAddress) -> None
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

    def connectToRemoteLEDevice(self, bt_addr, addr_type=0x00):
        # type: (BluetoothAddress, int) -> None
        """
        Send a HCI LE Create Connection Command to the firmware as
        defined in the Bluetooth Core Specification 5.0 p. 1266.
        
        bt_addr:  address of remote device (byte string)
                  e.g. for 'f8:95:c7:83:f8:11' you would pass
                  b'\xf8\x95\xc7\x83\xf8\x11'.
        addr_type: Public Device (0x00), Random Device (0x01), Public
                  Identity (0x02), Random static Identity (0x03).
        """

        # TODO: expose more of the connection create parameters (instead of
        #       passing 0's.
        self.sendHciCommand(0x200d, '\x60\x00\x30\x00\x00' + p8(addr_type) + bt_addr[::-1] + '\x01\x18\x00\x28\x00\x00\x00\xd0\x07\x00\x00\x00\x00')

    def connectionStatusCallback(self, record):
        # type: (Record) -> None
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

        # Also show Disconnect Complete
        if hcipkt.event_code == 0x05:
            conn_handle = u16(hcipkt.data[1:3])
            log.info("[Disconnect Complete: Handle=0x%x]" % (conn_handle))

    def coexStatusCallback(self, record):
        # type: (Record) -> None
        """
        Coexistence Callback Function
        Interprets debug counters for coexistence with WiFi/LTE
        Call with "sendhcicmd 0xfc90"
        """

        hcipkt    = record[0]   # get HCI Event packet
        timestamp = record[5]   # get timestamp

        if not issubclass(hcipkt.__class__, hci.HCI_Event):
            return

        # Command complete event with stats
        if hcipkt.event_code == 0x0e:
            if u16(hcipkt.data[1:3]) == 0xfc90: # Coex Statistics Cmd
                coex_grant = u32(hcipkt.data[4:8])
                coex_reject= u32(hcipkt.data[8:12])
                ratio = 0
                if coex_grant > 0:
                    ratio = coex_reject/float(coex_grant)
                log.info("[Coexistence Statistics: Grant=%d Reject=%d -> Reject Ratio %.4f]" % (coex_grant, coex_reject, ratio))
                return

    def readHeapInformation(self):
        # type: () -> Optional[Union[HeapInformation, bool]]
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
        - buffer_headers:   Dictionoary containing buffer headers (e.g. free linked list)
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
            # Parsing BLOC struct
            bloc_struct = self.readMem(current_bloc_struct_address, 0x30)

            # New Bloc Struct since ~2014
            if "BLOC_NG" in dir(self.fw):
                bloc_fields = struct.unpack("IHBBIIBB", bloc_struct[:18])
                current_element = {}
                current_element["index"]           = index
                current_element["address"]         = current_bloc_struct_address
                current_element["next"]            = bloc_fields[0]
                current_element["buffer_size"]     = bloc_fields[1]
                current_element["capacity"]        = bloc_fields[2]
                current_element["memory"]          = bloc_fields[4]
                current_element["buffer_list"]     = bloc_fields[5]
                current_element["list_length"]     = bloc_fields[6]

                current_element["memory_size"]     = current_element["capacity"] * (4+current_element["buffer_size"])

                #current_element["memory_size"]     = bloc_fields[6]
                #current_element["thread_waitlist"] = bloc_fields[8]
                #current_element["waitlist_length"] = bloc_fields[9]
                #current_element["prev"]            = bloc_fields[11]
                current_element["buffer_headers"]  = {}

            # Old BLOC Struct
            else:
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
                current_element["buffer_headers"]  = {}

            # Parsing buffer headers
            buffer_size  = current_element["buffer_size"] + 4
            for buf_index in range(current_element["capacity"]):
                buffer_address = current_element["memory"] + buf_index * buffer_size
                hdr = u32(self.readMem(buffer_address, 4))
                current_element["buffer_headers"][buffer_address] = hdr

            # Append and iterate
            bloclist.append(current_element)
            current_bloc_struct_address = current_element["next"]
            if current_bloc_struct_address == first_bloc_struct_address or current_bloc_struct_address == 0:
                break

        return bloclist


    def readQueueInformation(self):
        # type: () -> Optional[Union[bool, QueueInformation]]
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

    def enableBroadcomDiagnosticLogging(self, enable):
        # type: (bool) -> None
        """
        Broadcom implemented their own H4 layer protocol. Normally H4 handles HCI
        messages like HCI commands, SCO and ACL data, and HCI events. Their types are
        0x01-0x04. Broadcoms proprietary message type is 0x07 to handle diagnostic
        messages.
        
        Diagnostic logging sets a variable checked for any LMP/LCP message when
        sending and receiving and then forwarding its contents prepended with 0x07.
        In principle, diagnostic logging can be enabled on Android by directly
        writing to the serial Bluetooth device:
        
            echo -ne '\x07\xf0\x01' >/dev/ttyHS
        
        However, Androids Bluetooth driver is not properly parsing message type 0x07.
        This causes the driver to crash when enabling diagnostics like this. A
        custom Bluetooth driver is required, which accepts diagnostic commands
        and also forwards diagnostic message outputs to the BT Snoop Log.
        """

        if not self.serial:
            self.sendH4(hci.HCI.BCM_DIAG, '\xf0' + p8(enable))

        # We can send the activation to the serial, but then the Android driver
        # itself crashes when receiving diagnostic frames...
        else:
            log.warn("Diagnostic protocol requires modified Android driver!")

    def _setupSockets(self):
        raise NotImplementedError()

    def _teardownSockets(self):
        raise NotImplementedError()
