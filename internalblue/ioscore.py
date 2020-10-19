#!/usr/bin/env python2

from __future__ import absolute_import

from future import standard_library

standard_library.install_aliases()
from builtins import str
import socket
import queue as queue2k
from . import hci

from .usbmux import USBMux, MuxError
from .core import InternalBlue
import sys


class iOSCore(InternalBlue):
    buffer: bytes

    def __init__(
        self,
        queue_size=1000,
        btsnooplog_filename="btsnoop.log",
        log_level="info",
        data_directory=".",
    ):
        super(iOSCore, self).__init__(
            queue_size, btsnooplog_filename, log_level, data_directory="."
        )
        self.serial = False
        self.doublecheck = True
        self.buffer = b""
        self.muxconnecterror = False

        try:
            self.mux = USBMux()
        # on Linux, this can result in ConnectionRefusedError if no iOS device is present
        except ConnectionRefusedError:
            self.muxconnecterror = True

    def device_list(self):
        """
        Get a list of connected devices
        """

        # prevent access on non-available socket if usbmuxd failed
        if self.muxconnecterror:
            return []

        if self.exit_requested:
            self.shutdown()

        if self.running:
            self.logger.warn("Already running. Call shutdown() first!")
            return []

        # because we need to call process for every device that is connected
        # and we don't really know how much are connected, we just call process
        # 8 times (which should be a reasonable limit for the amount of connected
        # iOS devices) with a very short timeout.
        for i in range(0, 8):
            self.mux.process(0.01)

        self.devices = self.mux.devices
        if not self.devices:
            self.logger.info("No iOS devices connected")
        
        device_list = []
        for dev in self.devices:
            if sys.platform == "darwin":
                dev_id = "iOS Device (" + dev.serial + ")" # macos
            else:
                dev_id = "iOS Device (" + dev.serial.decode(
                    'utf-8') + ")"  
            device_list.append((self, dev, dev_id))

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
            self.logger.warn("sendH4: waiting for response timed out!")
            return None
        except queue2k.Full:
            self.logger.warn("sendH4: send queue is full!")
            return None

    def local_connect(self):
        """
        Start the framework by connecting to the iOS bluetooth device proxy via
        TCP
        """
        if not self._setupSockets():
            self.logger.critical("No connection to iPhone.")
            self.logger.info(
                "Check if\n \
                -> Bluetooth is deactivated in the iOS device's settings\n \
                -> internalblued is installed on the device\n \
                -> the device is connected to this computer via USB\n \
                -> usbmuxd is installed on this computer"
            )
            return False
        return True

    def _setupSockets(self):
        """
        Connect to the iOS Bluetooth device over usbmuxd and internalblued 
        """

        try:
            self.s_inject = self.mux.connect(self.interface, 1234)
        except MuxError:
            self.logger.warn("Could not connect to iOS proxy. Is internalblued running on the connected device?")
            return False
        
        self.s_inject.settimeout(0.5)

        # with on iOS the send and receive sockets are the same
        self.s_snoop = self.s_inject

        # empty the socket (can sometimes still hold data if the previous execution
        # of internalblue was cancelled or crashed)
        try:
            self.s_inject.recv(1024)
        except socket.error:
            pass

        return True

    def _getLatestH4Blob(self, new_data: bytes = b""):
        data_out: bytes = b""
        self.buffer += new_data
        if len(self.buffer) > 0:

            # if the buffer is too small, wait for more data
            if len(self.buffer) < 5:
                return (None, False)
            else:
                # for ACL data the length field is at offset 3
                if self.buffer[0] == 0x2:
                    acl_len = self.buffer[3]
                    required_len = acl_len + 5
                # for HCI cmd data the length is at offset 3 (but just one byte)
                elif self.buffer[0] == 0x1:
                    hci_len = self.buffer[3]
                    required_len = hci_len + 4
                # for HCI event data the length is at offset 2 (one byte)
                elif self.buffer[0] == 0x4:
                    hci_len = self.buffer[2]
                    required_len = hci_len + 3
                # for BCM data the length should always be 64
                elif self.buffer[0] == 0x07:
                    required_len = 64
                else:
                    raise ValueError("Could not derive required_len from buffer")

                # if we don't have all the data we need, we just wait for more
                if len(self.buffer) < required_len:
                    return (None, False)
                # might be the case that we have too much
                elif len(self.buffer) > required_len:
                    self.logger.info(
                        "Got too much data, expected %d, got %d",
                        required_len,
                        len(self.buffer),
                    )
                    surplus = len(self.buffer) - required_len
                    new_buffer = self.buffer[required_len : len(self.buffer)]
                    data_out = self.buffer[:-surplus]
                    self.buffer = new_buffer
                    return (data_out, True)
                # sometimes we even have just the right amout of data
                else:
                    data_out = self.buffer
                    self.buffer = b""
                    return (data_out, False)
        else:
            return (None, False)

    def _recvThreadFunc(self):

        self.logger.debug("Receive Thread started.")

        if self.write_btsnooplog:
            self.logger.warn("Writing btsnooplog is not supported with iOS.")

        while not self.exit_requested:
            # read record data
            try:
                received_data = self.s_snoop.recv(1024)
            except socket.timeout:
                continue  # this is ok. just try again without error

            self.logger.debug("H4 Data: %s", received_data)

            (record_data, is_more) = self._getLatestH4Blob(new_data=received_data)
            while record_data is not None:
                # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
                record = (hci.parse_hci_packet(record_data), 0, 0, 0, 0, 0)

                self.logger.debug("Recv: " + str(record[0]))

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
                    except queue2k.Full:
                        self.logger.warn(
                            "recvThreadFunc: A recv queue is full. dropping packets.."
                        )

                # Call all callback functions inside registeredHciCallbacks and pass the
                # record as argument.
                for callback in self.registeredHciCallbacks:
                    callback(record)

                # Check if the stackDumpReceiver has noticed that the chip crashed.
                if self.stackDumpReceiver.stack_dump_has_happened:
                    # A stack dump has happened!
                    self.logger.warn(
                        "recvThreadFunc: The controller send a stack dump. stopping.."
                    )
                    self.exit_requested = True

                (record_data, is_more) = self._getLatestH4Blob()
                if not is_more:
                    break

        self.logger.debug("Receive Thread terminated.")

    def _teardownSockets(self):
        """
        Close s_snoop and s_inject (which are the same)
        """

        if self.s_inject is not None:
            self.s_inject.close()
            self.s_inject = None

        return True
