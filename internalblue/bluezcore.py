#!/usr/bin/env python2

import subprocess
from pwn import *
import fcntl
from core import InternalBlue
import hci
import Queue

# from /usr/include/bluetooth/hci.h:
#define HCIDEVUP	_IOW('H', 201, int)
#define HCIGETDEVLIST	_IOR('H', 210, int)
#define HCIGETDEVINFO	_IOR('H', 211, int)

# ioctl numbers. see http://code.activestate.com/recipes/578225-linux-ioctl-numbers-in-python/
def _IOR(type, nr, size):
    return 2 << 30 | type << 8 | nr << 0 | size << 16
def _IOW(type, nr, size):
    return 1 << 30 | type << 8 | nr << 0 | size << 16

HCIDEVUP      = _IOW(ord('H'), 201, 4)
HCIGETDEVLIST = _IOR(ord('H'), 210, 4)
HCIGETDEVINFO = _IOR(ord('H'), 211, 4)


class BluezCore(InternalBlue):

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(BluezCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")

    def getHciDeviceList(self):
        """
        Get a list of available HCI devices. The list is obtained by executing
        ioctl syscalls HCIGETDEVLIST and HCIGETDEVINFO. The returned list 
        contains dictionaries with the following fields:
            dev_id          : Internal ID of the device (e.g. 0)
            dev_name        : Name of the device (e.g. "hci0")
            dev_bdaddr      : MAC address (e.g. "00:11:22:33:44:55")
            dev_flags       : Device flags as decimal number
            dev_flags_str   : Device flags as String (e.g. "UP RUNNING" or "DOWN")
        """

        # Open bluetooth socket to execute ioctl's:
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)

        # Do ioctl(s,HCIGETDEVLIST,arg) to get the number of available devices:
        # arg is struct hci_dev_list_req (/usr/include/bluetooth/hci.h)
        arg =  p32(16) # dl->dev_num = HCI_MAX_DEV which is 16 (little endian)
        arg += "\x00"*(8*16)
        devices_raw = fcntl.ioctl(s.fileno(), HCIGETDEVLIST, arg)
        num_devices = u16(devices_raw[:2])
        log.debug("Found %d HCI devices via ioctl(HCIGETDEVLIST)!" % num_devices)

        device_list = []
        for dev_nr in range(num_devices):
            dev_struct_start = 4 + 8*dev_nr
            dev_id = u16(devices_raw[dev_struct_start:dev_struct_start+2])
            # arg is struct hci_dev_info (/usr/include/bluetooth/hci.h)
            arg =  p16(dev_id) # di->dev_id = <device_id>
            arg += "\x00"*20   # Enough space for name, bdaddr and flags
            dev_info_raw = fcntl.ioctl(s.fileno(), HCIGETDEVINFO, arg)
            dev_name   = dev_info_raw[2:10].replace("\x00","")
            dev_bdaddr = ":".join(["%02X" % ord(x) for x in dev_info_raw[10:16][::-1]])
            dev_flags  = u32(dev_info_raw[16:20])
            if dev_flags == 0:
                dev_flags_str = "DOWN"
            else:
                dev_flags_str = " ".join([name for flag,name in zip(
                                bin(dev_flags)[2:][::-1],
                                ["UP", "INIT", "RUNNING", "PSCAN", "ISCAN", "AUTH",
                                 "ENCRYPT" , "INQUIRY" , "RAW" , "RESET"]) if flag=="1"])

            device_list.append({"dev_id":        dev_id,
                                "dev_name":      dev_name,
                                "dev_bdaddr":    dev_bdaddr,
                                "dev_flags":     dev_flags,
                                "dev_flags_str": dev_flags_str})
        s.close()
        return device_list

    def bringHciDeviceUp(self, dev_id):
        """
        Uses HCIDEVUP ioctl to bring HCI device with id dev_id up.
        Requires root priviledges (CAP_NET_ADMIN).
        """

        if dev_id < 0 or dev_id > 16:
            log.warn("bringHciDeviceUp: Invalid device id: %d." % dev_id)
            return False

        # Open bluetooth socket to execute ioctl's:
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)

        # Do ioctl(s, HCIDEVUP, dev_id) to bring device up:
        try:
            fcntl.ioctl(s.fileno(), HCIDEVUP, dev_id)
            s.close()
            log.info("Device with id=%d was set up successfully!" % dev_id)
            return True
        except IOError as e:
            s.close()
            log.warn("Error returned by ioctl: %s" % str(e))
            return False


    def device_list(self):
        """
        Return a list of connected hci devices.
        """

        device_list = []
        for dev in self.getHciDeviceList():
            log.info("HCI device: %s  [%s]  flags=%d<%s>" %
                    (dev["dev_name"], dev["dev_bdaddr"],
                     dev["dev_flags"], dev["dev_flags_str"]))
            device_list.append([self, dev["dev_name"], 'hci: %s (%s) <%s>' %
                    (dev["dev_bdaddr"], dev["dev_name"], dev["dev_flags_str"])])

        if len(device_list) == 0:
            log.info('No connected HCI device found')

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
            # if self.stackDumpReceiver.stack_dump_has_happend:
                # A stack dump has happend!
                # log.warn("recvThreadFunc: The controller send a stack dump.")
                # self.exit_requested = True

        log.debug("Receive Thread terminated.")

    def _setupSockets(self):
        """
        Linux already allows to open HCI sockets to Bluetooth devices,
        they include H4 information, we simply use it.
        """

        # Check if hci device is in state "UP". If not, set it to "UP" (requires root)
        device = [dev for dev in self.getHciDeviceList() if dev["dev_name"] == self.interface]
        if len(device) == 0:
            log.warn("Device not found: " + self.interface)
            return False
        device = device[0]

        if device["dev_flags"] == 0:
            log.warn("Device %s is DOWN!" % self.interface)
            log.info("Trying to set %s to state 'UP' (requires root)" % self.interface)
            if not self.bringHciDeviceUp(device["dev_id"]):
                log.warn("Failed to bring up %s." % self.interface)
                return False

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
