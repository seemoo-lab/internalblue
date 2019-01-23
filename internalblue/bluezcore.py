#!/usr/bin/env python2

#from multiprocessing import Process, Queue
import subprocess

#from Queue import Empty as QueueEmpty
import re
from time import sleep

from pwn import *

from core import InternalBlue
#from hci import HCI_Cmd, HCI_Event
import hci
import Queue




class BluezCore(InternalBlue):

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(BluezCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")
        
        # TODO move to a config file or solve with ioctl / HCIGETDEVLIST / 210
        self.hcitoollist = 'hcitool dev' # does not require root, so we ask for sudo later

    def device_list(self):
        """
        Return a list of connected hci devices
        """

        response = subprocess.check_output(self.hcitoollist.split()).split()

        device_list = []
        # checks if a hci device is connected
        if len(response) > 1 and len(response) % 2 == 1:
            response = response[1:]
            for interface, address in zip(response[0::2], response[1::2]):
                device_list.append([self, interface, 'hci: %s (%s)' % (address, interface)])

        if len(device_list) == 0:
            log.info('No connected HCI device found')
            return []
        elif len(device_list) == 1:
            log.info('Found one HCI device, %s' % device_list[0][2])
        else:
            log.info('Found multiple HCI devices')

        return device_list

    def local_connect(self):
        """
        """

        if not self.interface:
            log.warn("No HCI identifier is set")
            return False
        
        if not self._setupSockets():
            log.critical("bluez socket could not be established!")
            return False

        return True

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
        
        if (self.write_btsnooplog):
            log.warn("Writing btsnooplog is not supported with bluez.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # Read the record data
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

    def _setupSockets(self):
        """
        bluez already allows to open sockets to Bluetooth devices on Linux,
        they include H4 information, we simply use it.
        """

        # In order to support multiple parallel instances of InternalBlue
        # (with multiple attached devices) we must not hard code the
        # forwarded port numbers. Therefore we choose the port numbers
        # randomly and hope that they are not already in use.

        # TODO unload btusb module and check error messages here to give the user some output if sth fails

        # Connect to HCI socket
        self.s_snoop = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self.s_snoop.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR,1)
        self.s_snoop.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP,1)
        """
        struct hci_filter {
            uint32_t type_mask;     -> 4
            uint32_t event_mask[2]; -> 8
            uint16_t opcode;        -> 2
        };
        """
        # TODO still seems to only forward incoming events?!
        self.s_snoop.setsockopt(socket.SOL_HCI, socket.HCI_FILTER,
 '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00') #type mask, event mask, event mask, opcode
        
        interface_num = int(self.interface.replace('hci', ''))
        log.debug("Socket interface number: %s" % (interface_num))
        self.s_snoop.bind((interface_num,))
        self.s_snoop.settimeout(2)
        
        # same socket for input and output (bluez is different from adb here!)
        self.s_inject = self.s_snoop
        
        
        log.debug("_setupSockets: Bound socket.")
        
        #while True:
        #    log.debug(self.s_snoop.recv(1024).encode('hex'))
            
        return True

    def _teardownSockets(self):
        """
        Close s_snoop and s_inject socket. (equal)
        """

        if (self.s_inject != None):
            self.s_inject.close()
            self.s_inject = None

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

        # bluez does not require a data length here
        #data = p16(len(data)) + data #TODO

        try:
            self.sendQueue.put((h4type, data, queue), timeout=timeout)
            ret = queue.get(timeout=timeout)
            return ret
        except Queue.Empty:
            log.warn("sendH4: waiting for response timed out!")
            return None
        except Queue.Full:
            # seems to happen quite often on a busy stack, but most of the time
            # messages get through
            log.info("sendH4: send queue is full!")
            return None
