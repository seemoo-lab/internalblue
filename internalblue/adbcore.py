#!/usr/bin/env python2

import socket
import Queue
import random
import hci

from pwn import *

from core import InternalBlue


class ADBCore(InternalBlue):

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(ADBCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")

    def device_list(self):
        """
        Get a list of the connected devices
        """

        if self.exit_requested:
            self.shutdown()

        if self.running:
            log.warn("Already running. call shutdown() first!")
            return []

        # Check for connected adb devices
        try:
            adb_devices = adb.devices()
        except:
            adb_devices = 0
        
        if(len(adb_devices) == 0):
            log.info("No adb devices found.")
            return []

        # At least one device fonund
        log.info("Found multiple adb devices")

        # Enumerate over found devices and put them into an array of tupple
        # First index is a self reference of the class
        # Scond index is the identifier which is passed to connect()
        # Third index is the label which is shown in options(...)
        device_list = []
        for d in adb_devices:
            device_list.append((self, d.serial, 'adb: %s (%s)' % (d.serial, d.model)))

        return device_list

    def local_connect(self):
        """
        Start the framework by connecting to the Bluetooth Stack of the Android
        device via adb and the debugging TCP ports.
        """

        # Connect to adb device
        context.device = self.interface

        # setup sockets
        if not self._setupSockets():
            log.critical("No connection to target device.")
            log.info("Check if:\n -> Bluetooth is active\n -> Bluetooth Stack has Debug Enabled\n -> BT HCI snoop log is activated\n")
            return False

        return True

    def sendH4(self, h4type, data, timeout=2):
        """
        Send an arbitrary HCI packet by pushing a send-task into the
        sendQueue. This function blocks until the response is received
        or the timeout expires. The return value is the Payload of the
        HCI Command Complete Event which was received in response to
        the command or None if no response was received within the timeout.
        """
        #TODO: If the response is a HCI Command Status Event, we will actually
        #      return this instead of the Command Complete Event (which will
        #      follow later and will be ignored). This should be fixed..

        queue = Queue.Queue(1)

        # prepend with total length for H4 over adb 
        data = p16(len(data)) + data

        try:
            self.sendQueue.put((h4type, data, queue), timeout=timeout)
            ret = queue.get(timeout=timeout)
            return ret
        except Queue.Empty:
            log.warn("sendH4: waiting for response timed out!")
            return None
        except Queue.Full:
            log.warn("sendH4: send queue is full!")
            return None

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
                    log.debug(recv_data.encode('hex'))
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
        log.debug("_setupSockets: Selected random ports snoop=%d and inject=%d" % (self.hciport, self.hciport + 1))

        # Forward ports 8872 and 8873. Ignore log.info() outputs by the adb function.
        saved_loglevel = context.log_level
        context.log_level = 'warn'
        try:
            adb.adb(["forward", "tcp:%d" % (self.hciport), "tcp:8872"])
            adb.adb(["forward", "tcp:%d" % (self.hciport + 1), "tcp:8873"])
        except PwnlibException as e:
            log.warn("Setup adb port forwarding failed: " + str(e))
            return False
        finally:
            context.log_level = saved_loglevel

        # Connect to hci injection port
        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_inject.connect(('127.0.0.1', self.hciport + 1))
        self.s_inject.settimeout(0.5)

        # Connect to hci snoop log port
        self.s_snoop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_snoop.connect(('127.0.0.1', self.hciport))
        self.s_snoop.settimeout(0.5)

        # Read btsnoop header
        if (self._read_btsnoop_hdr() == None):
            log.warn("Could not read btsnoop header")
            self.s_inject.close()
            self.s_snoop.close()
            self.s_inject = self.s_snoop = None
            adb.adb(["forward", "--remove", "tcp:%d" % (self.hciport)])
            adb.adb(["forward", "--remove", "tcp:%d" % (self.hciport + 1)])
            return False
        return True

    def _teardownSockets(self):
        """
        Close s_snoop and s_inject sockets. Remove port forwarding with adb.
        """

        if (self.s_inject != None):
            self.s_inject.close()
            self.s_inject = None
        if (self.s_snoop != None):
            self.s_snoop.close()
            self.s_snoop = None

        saved_loglevel = context.log_level
        context.log_level = 'warn'
        try:
            adb.adb(["forward", "--remove", "tcp:%d" % (self.hciport)])
            adb.adb(["forward", "--remove", "tcp:%d" % (self.hciport + 1)])
        except PwnlibException as e:
            log.warn("Removing adb port forwarding failed: " + str(e))
            return False
        finally:
            context.log_level = saved_loglevel
