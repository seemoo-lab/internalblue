#!/usr/bin/env python2

from __future__ import absolute_import

import struct

from future import standard_library
standard_library.install_aliases()
from builtins import str
import socket
import queue as queue2k
from . import hci

from internalblue.utils.pwnlib import log, context

from .core import InternalBlue

class iOSCore(InternalBlue):

    def __init__(self, ios_addr, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(iOSCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")
        parts = ios_addr.split(':')
        if len(parts) != 2:
            log.critical("iOS device address should be of format HOSTNAME:PORT")
            exit(-1)
        self.ios_addr = parts[0]
        self.ios_port = parts[1]
        self.serial = False
        self.doublecheck = True
        self.buffer = ""

    def device_list(self):
        """
        Get a list of connected devices
        """

        if self.exit_requested:
            self.shutdown()

        if self.running:
            log.warn("Already running. Call shutdown() first!")
            return []

        # assume that a explicitly specified iPhone exists
        device_list = []
        device_list.append((self, "iPhone", "iPhone"))

        return device_list

    def sendH4(self, h4type, data, timeout=0.5):
        """
        Send an arbitrary HCI packet by pushing a send-task into the
        sendQueue. This function blocks until the response is received
        or the timeout expires. The return value is the Payload of the
        HCI Command Complete Event which was received in response to
        the command or None if no response was received within the timeout.
        """

        queue = queue2k.Queue(1)

        try:
            self.sendQueue.put((h4type, data, queue, None), timeout=timeout)
            ret = queue.get(timeout=timeout)
            return ret
        except queue2k.Empty:
            log.warn("sendH4: waiting for response timed out!")
            return None
        except queue.Full:
            log.warn("sendH4: send queue is full!")
            return None

    def local_connect(self):
        """
        Start the framework by connecting to the iOS bluetooth device proxy via
        TCP
        """
        if not self._setupSockets():
            log.critical("No connection to iPhone.")
            log.info("Check if\n -> Bluetooth is deactivated in the iPhone settings\n -> internalblue-ios-proxy is running\n -> the proxied port is accesible from this machine")
            return False
        return True

    def _setupSockets(self):
        """
        Connect to the iOS bluetooth device over internalblue-ios-proxy
        """

        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s_inject.connect((self.ios_addr, int(self.ios_port)))
            self.s_inject.settimeout(0.5)
        except socket.error:
            log.warn("Could not connect to iPhone, is internalblue-ios-proxy running?")
            return False

        # with ios proxy the send and receive sockets are the same
        self.s_snoop = self.s_inject

        return True

    def _getLatestH4Blob(self, new_data=""):
        data_out = ""
        self.buffer += new_data
        if len(self.buffer) > 0:
        
            # if the buffer is too small, wait for more data
            if len(self.buffer) < 5:
                return (None, False)
            else:
                #log.info(self.buffer[0].encode("hex"))
                # for ACL data the length field is at offset 3
                if self.buffer[0] == '\x02':
                    acl_len = struct.unpack_from("h", self.buffer[3:])[0]
                    required_len = acl_len + 5
                # for HCI cmd data the length is at offset 3 (but just one byte)
                elif self.buffer[0] == '\x01':
                    hci_len = struct.unpack_from("b", self.buffer[3:])[0]
                    required_len = hci_len + 4
                # for HCI event data the length is at offset 2 (one byte)
                elif self.buffer[0] == '\x04':
                    hci_len = struct.unpack_from("b", self.buffer[2:])[0]
                    required_len = hci_len + 3
                # for BCM data the length should always be 64
                elif self.buffer[0] == '\x07':
                    required_len = 64

                # if we don't have all the data we need, we just wait for more
                if len(self.buffer) < required_len:
                    #log.info("Not enough data, expected %d, got %d", required_len, len(self.buffer))
                    return (None, False)
                # might be the case that we have too much
                elif len(self.buffer) > required_len:
                    log.info("Got too much data, expected %d, got %d", required_len, len(self.buffer))
                    surplus = len(self.buffer) - required_len 
                    new_buffer = self.buffer[required_len:len(self.buffer)]
                    data_out = self.buffer[:-surplus]
                    #log.info("new_buffer: %s, data_out: %s", new_buffer.encode("hex"), data_out.encode("hex"))
                    self.buffer = new_buffer
                    return (data_out, True)
                # sometimes we even have just the right amout of data
                else:
                    #log.info("Got exactly the right amount of data")
                    data_out = self.buffer
                    self.buffer = ""
                    return (data_out, False)
        else:
            return (None, False)

    def _recvThreadFunc(self):

        log.debug("Receive Thread started.")

        if self.write_btsnooplog:
            log.warn("Writing btsnooplog is not supported with iOS.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # read record data
            try:
                received_data = self.s_snoop.recv(1024)
            except socket.timeout:
                continue # this is ok. just try again without error
                
            # because the iOS socket is rather unreliable (blame the iOS proxy developer) we
            # need to do some length checks and get the H4/HCI data in the right format
            #log.info("H4 Data received")
            #log.info(received_data.encode('hex'))
            
            (record_data, is_more) = self._getLatestH4Blob(new_data=received_data)
            while record_data is not None:
                # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
                record = (hci.parse_hci_packet(record_data), 0, 0, 0, 0, 0) 

                log.debug("Recv: " + str(record[0]))

                # Put the record into all queues of registeredHciRecvQueues if their
                # filter function matches.
                for queue, filter_function in self.registeredHciRecvQueues: # TODO filter_function not working with bluez modifications
                    try:
                        queue.put(record, block=False)
                    except queue.Full:
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
                
                (record_data, is_more) = self._getLatestH4Blob()
                if not is_more:
                    break

        log.debug("Receive Thread terminated.")

    def _teardownSockets(self):
        """
        Close s_snoop and s_inject (which are the same)
        """

        if (self.s_inject != None):
            self.s_inject.close()
            self.s_inject = None

        return True

