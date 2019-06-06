#!/usr/bin/env python2

import socket
import Queue
import hci

from pwn import *

from core import InternalBlue

class iOSCore(InternalBlue):

    def __init__(self, ios_addr, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(iOSCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")
        parts = ios_addr.split(':')
        if len(parts) != 2:
            log.critical("iOS device address should be of format HOSTNAME:PORT")
            exit(-1)
        self.ios_addr = parts[0]
        self.ios_port = parts[1]

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

    def sendH4(self, h4type, data, timeout=2):
        """
        Send an arbitrary HCI packet by pushing a send-task into the
        sendQueue. This function blocks until the response is received
        or the timeout expires. The return value is the Payload of the
        HCI Command Complete Event which was received in response to
        the command or None if no response was received within the timeout.
        """

        queue = Queue.Queue(1)

        try:
            self.sendQueue.put((h4type, data, queue, None), timeout=timeout)
            ret = queue.get(timeout=timeout)
            return ret
        except Queue.Empty:
            log.warn("sendH4: waiting for response timed out!")
            return None
        except Queue.Full:
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

    def _recvThreadFunc(self):

        log.debug("Receive Thread started.")

        if (self.write_btsnooplog):
            log.warn("Writing btsnooplog is not supported with iOS.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # read record data
            try:
                record_data = self.s_snoop.recv(1024)
            except socket.timeout:
                continue # this is ok. just try again without error

            # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
            record = (hci.parse_hci_packet(record_data), 0, 0, 0, 0, 0) #TODO not sure if this causes trouble?

            log.debug("Recv: " + str(record[0]))

            # Put the record into all queues of registeredHciRecvQueues if their
            # filter function matches.
            for queue, filter_function in self.registeredHciRecvQueues: # TODO filter_function not working with bluez modifications
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

    def _teardownSockets(self):
        """
        Close s_snoop and s_inject (which are the same)
        """

        if (self.s_inject != None):
            self.s_inject.close()
            self.s_inject = None

        return True

