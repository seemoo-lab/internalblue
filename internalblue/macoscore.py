#!/usr/bin/env python2

from __future__ import absolute_import

import os
import random
import time

from future import standard_library

standard_library.install_aliases()
from builtins import str
import socket
import queue as queue2k
from . import hci

from internalblue.utils.pwnlib_wrapper import context, p8
from .core import InternalBlue



filepath = os.path.dirname(os.path.abspath(__file__))

IOBE = None


# noinspection SpellCheckingInspection
class macOSCore(InternalBlue):
    def __init__(
            self,
            queue_size=1000,
            btsnooplog_filename="btsnoop.log",
            log_level="info",
            fix_binutils="True",
            data_directory=".",
            replay=False,
    ):
        super(macOSCore, self).__init__(
            queue_size,
            btsnooplog_filename,
            log_level,
            fix_binutils,
            data_directory=".",
            replay=replay,
        )
        self.doublecheck = False
        self.iobe = None
        self.serial = None
        if not replay:
            import objc  # type: ignore

            objc.initFrameworkWrapper(
                "IOBluetoothExtended",
                frameworkIdentifier="de.tu-darmstadt.seemoo.IOBluetoothExtended",
                frameworkPath=objc.pathForFramework(
                    filepath + "/../macos/IOBluetoothExtended.framework"
                ),
                globals=globals(),
            )
        self.hciport = -1

    def device_list(self):
        """
        Get a list of connected devices
        """

        if self.exit_requested:
            self.shutdown()

        if self.running:
            self.logger.warning("Already running. Call shutdown() first!")
            return []

        # assume that a explicitly specified iPhone exists
        device_list = [(self, "mac", "mac")]

        return device_list

    def local_connect(self):
        if not self._setupSockets():
            self.logger.critical("No connection to target device.")
            self._teardownSockets()
        return True

    def _setupSockets(self):
        self.hciport = random.randint(60000, 65535 - 1)
        self.logger.debug(
            "_setupSockets: Selected random ports snoop=%d and inject=%d"
            % (self.hciport, self.hciport + 1)
        )
        self.logger.info(
            "Wireshark configuration (on Loopback interface): udp.port == %d || udp.port == %d"
            % (self.hciport, self.hciport + 1)
        )

        # Create s_snoop socket
        self.s_snoop = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s_snoop.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s_snoop.bind(("127.0.0.1", self.hciport))
        self.s_snoop.settimeout(0.5)
        self.s_snoop.setblocking(True)

        # Create s_inject
        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s_inject.settimeout(0.5)
        self.s_inject.setblocking(True)

        # Create IOBluetoothExtended Object that listens for commands,
        # sends them to the Bluetooth chip and replies via UDP socket.
        if not self.replay:
            self.iobe = IOBE.alloc().initWith_and_(
                str(self.hciport + 1), str(self.hciport)
            )
        else:
            self.iobe = None
        time.sleep(0.5)

        return True

    def _recvThreadFunc(self):

        self.logger.debug("Receive Thread started.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # read record data
            try:
                data, addr = self.s_snoop.recvfrom(1024)
                record_data = bytearray(data)
            except socket.timeout:
                continue  # this is ok. just try again without error

            if not self.exit_requested:
                # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
                record = (
                    hci.parse_hci_packet(record_data),
                    0,
                    0,
                    0,
                    0,
                    0,
                )  # TODO not sure if this causes trouble?
                # self.logger.debug("Recv: " + str(record[0]))

                # Put the record into all queues of registeredHciRecvQueues if their
                # filter function matches.
                for (
                        queue,
                        filter_function,
                ) in (
                        self.registeredHciRecvQueues
                ):  # TODO filter_function not working with bluez modifications
                    try:
                        queue.put(record, block=False)
                    except queue.Full:
                        self.logger.warning(
                            "recvThreadFunc: A recv queue is full. dropping packets..>"
                            + str(record_data)
                        )

                # Call all callback functions inside registeredHciCallbacks and pass the
                # record as argument.
                for callback in self.registeredHciCallbacks:
                    callback(record)

        self.logger.debug("Receive Thread terminated.")

    def _sendThreadFunc(self):
        self.logger.debug("Send Thread started.")
        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # Wait for 'send task' in send queue
            try:
                task = self.sendQueue.get(timeout=0.5)
            except queue2k.Empty:
                continue

            # Extract the components of the task
            h4type, data, queue, filter_function = task

            # Prepend UART TYPE and length.
            out = p8(h4type) + p8(len(data)) + data

            # Send command to the chip using IOBluetoothExtended framework
            h4type, data, queue, filter_function = task
            data = bytearray(data)
            opcode = format(data[1], "02x") + format(data[0], "02x")

            # TODO: - Only print debug messages when debug variable is set!
            # self.logger.debug(
            #     "Sending command: 0x"
            #     + "".join(format(x, "02x") for x in data)
            #     + ", opcode: "
            #     + opcode
            # )

            if not (h4type == 0x01 or h4type == 0x02):
                self.logger.warn("H4 Type {0} not supported by macOS Core!".format(str(h4type)))
                if queue is not None:
                    queue.put(None)
                continue

            # if the caller expects a response: register a queue to receive the response
            if queue is not None and filter_function is not None:
                recvQueue = queue2k.Queue(1)
                self.registerHciRecvQueue(recvQueue, filter_function)

            # Sending command
            self.s_inject.sendto(out, ("127.0.0.1", self.hciport + 1))

            # if the caller expects a response:
            # Wait for the HCI event response by polling the recvQueue
            if queue is not None and filter_function is not None:
                try:
                    record = recvQueue.get(timeout=10)
                    hcipkt = record[0]
                    data = hcipkt.data
                except queue2k.Empty:
                    self.logger.warning("_sendThreadFunc: No response from the firmware.")
                    data = None
                    self.unregisterHciRecvQueue(recvQueue)
                    continue

                queue.put(data)
                self.unregisterHciRecvQueue(recvQueue)

        self.logger.debug("Send Thread terminated.")

    def _teardownSockets(self):
        if self.s_inject is not None:
            self.s_inject.close()
            self.s_inject = None

        if self.s_snoop is not None:
            self.s_snoop.close()
            self.s_snoop = None

        return True

    def shutdown(self):
        if not self.replay:
            self.iobe.shutdown()
        self.s_inject.sendto(b"", ("127.0.0.1", self.s_snoop.getsockname()[1]))
        super(macOSCore, self).shutdown()
