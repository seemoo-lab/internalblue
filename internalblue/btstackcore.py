#!/usr/bin/env python3

from future import standard_library

import datetime
import time
import socket
import struct
import queue as queue2k

from . import hci
from .core import InternalBlue
standard_library.install_aliases()

# BTstack Daemon defaults
BTSTACK_SERVER_HOST = "localhost"
BTSTACK_SERVER_TCP_PORT = 13333

# BTstack defines
OGF_BTSTACK = 0x3d
BTSTACK_EVENT_STATE = 0x60
BTSTACK_EVENT_POWERON_FAILED = 0x62

class BTstackCore(InternalBlue):
    global BTSTACK_SERVER_TCP_PORT
    global BTSTACK_SERVER_HOST

    def __init__(
        self,
        tcp_port=BTSTACK_SERVER_TCP_PORT,
        tcp_host=BTSTACK_SERVER_HOST,
        queue_size=1000,
        btsnooplog_filename=None,
        log_level='info',
        data_directory=".",
        replay=False
    ):

        super(BTstackCore, self).__init__(
            queue_size,
            btsnooplog_filename,
            log_level,
            data_directory,
            replay
        )

        self.tcp_port = tcp_port
        self.tcp_host = tcp_host
        self.s_inject = None
        self.serial = False

    def device_list(self):
        """
        Get a list of the connected devices
        """

        if self.exit_requested:
            self.shutdown()

        if self.running:
            self.logger.warn("Already running. call shutdown() first!")
            return []

        return ["BTstack Daemon"]

    def _recvPacket(self):
        # format: packet type, channel, len, payload
        header = self.s_inject.recv(6)
        (packet_type, channel, length) = struct.unpack("<HHH", header)
        payload = self.s_inject.recv(length)
        return packet_type, channel, length, payload

    def local_connect(self):
        # Connect to BTstack Daemon via TCP
        return self._setupSockets()

    def _recvThreadFunc(self):

        """
        This is the run-function of the recvThread. It receives HCI packets from the
        btstack socket.
        Received HCI packets are being put into the queues inside registeredHciRecvQueues and
        passed to the callback functions inside registeredHciCallbacks.
        The thread stops when exit_requested is set to True. It will do that on its own
        if it encounters a fatal error or the stackDumpReceiver reports that the chip crashed.
        """

        self.logger.debug("Receive Thread started.")

        while not self.exit_requested:

            # receive packet
            (packet_type, channel, length, payload) = self._recvPacket()
            received_time = datetime.datetime.now()

            # Put relevant info into a tuple. The HCI packet is parsed with the help of hci.py.
            orig_len = length
            inc_len = length
            # flags
            # - 1 for incoming
            # - 2 for command/event
            flags = 1
            if packet_type == 4:
                flags |= 2
            drops = 0
            record = (hci.parse_hci_packet(bytes([packet_type]) + payload), orig_len, inc_len, flags, drops, received_time)

            # Put the record into all queues of registeredHciRecvQueues if their
            # filter function matches.
            for queue, filter_function in self.registeredHciRecvQueues:
                if filter_function == None or filter_function(record):
                    try:
                        queue.put(record, block=False)
                    except queue2k.Full:
                        self.logger.warning(
                            "recvThreadFunc: A recv queue is full. dropping packets.."
                        )

            # Call all callback functions inside registeredHciCallbacks and pass the
            # record as argument.
            for callback in self.registeredHciCallbacks:
                callback(record)

        self.logger.debug("Receive Thread terminated.")

    def _setupSockets(self):
        """
        Start the framework by connecting to the BTstack daemon via TCP and tell it to power up
        """
        self.logger.info("Connect to server on %s:%u" % (self.tcp_host, self.tcp_port))
        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout = time.time() + 3
        btstack_state = "OFF"

        try:
            self.s_inject.connect((self.tcp_host, self.tcp_port))

            # send power on
            power_on = struct.pack("<HBB", (OGF_BTSTACK << 10) | 2, 1, 1)
            header = struct.pack("<HHH", 1, 0, len(power_on))
            out = header + power_on
            self.s_inject.send(out)

            # wait for state working or failed
            while (not self.exit_requested) and btstack_state == 'OFF':
                (packet_type, channel, length, payload) = self._recvPacket()
                if packet_type == 4:
                    if length > 0:
                        if payload[0] == BTSTACK_EVENT_STATE and length == 3 and payload[2] == 2:
                            btstack_state = "WORKING"
                            self.logger.info("BTstack working")
                        if payload[0] == BTSTACK_EVENT_POWERON_FAILED:
                            btstack_state = "FAILED"
                            self.logger.error("BTstack startup failed")

        except socket.error as e:
            if time.time() > timeout:
                self.logger.error("[!] Connection error: %s" % e)
                return False

        connected = btstack_state == "WORKING"
        return connected

    def _teardownSockets(self):
        """
        Close s_inject sockets.
        """

        if self.s_inject is not None:
            self.s_inject.close()
            self.s_inject = None
        return False
