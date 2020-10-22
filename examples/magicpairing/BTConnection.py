# This class can be used to create a bluetooth connection
# to a remote device. currently it only supports unauthenticated
# connections. in general, it is very basic and offers the bare minimum
# to semi-reliably hold an active l2cap channel.

import binascii
import struct
import threading
import time

from pwnlib import log

import internalblue.hci as hci
from internalblue.utils import p16, p8

CONNECTION_TYPE_CLASSIC = 0
CONNECTION_TYPE_BLE = 1


class BluetoothConnection:
    def __init__(self, core, bd_addr, reconnect=1, keepalive=True, timeout=5):
        self.core = core
        self.remote_addr = bd_addr
        self.reconnect = reconnect
        self.keepalive = keepalive
        self.timeout = timeout

        # the handle also determines whether there is currently an active connection
        self.handle = None
        self.aclHandlers = []
        self.reconnect_counter = 0
        self.keepalive_active = False
        self.link_keys = {}
        self.encrypted = False
        self.started_connection = False
        # connection type can be either 0 (classic) or 1 (ble), default is classic 
        self.connection_type = CONNECTION_TYPE_CLASSIC

        self.connection_callback = None
        self.encryption_callback = None

        self.core.registerHciCallback(self._callback)

    def _keepaliveTimer(self):
        if self.keepalive and self.handle:
            self._sendKeepalive()
        if self.keepalive_active:
            threading.Timer(1, self._keepaliveTimer).start()

    def _sendKeepalive(self):
        pass

    def _callback(self, record):
        h4_record = record[0]

        if issubclass(h4_record.__class__, hci.HCI_Event):
            self._hciEventHandler(h4_record)
        elif issubclass(h4_record.__class__, hci.HCI_Acl):
            self._aclEventHandler(h4_record.getRaw())

    def _hciEventHandler(self, h4_record):
        event = h4_record.event_code
        hci_data = h4_record.data
        status = hci_data[0]

        # connection complete event
        if event == 3:
            # connection complete - sucess
            if status == 0:
                handle = struct.unpack_from("h", hci_data[1:])[0]
                self.handle = handle
                log.info("Connection to %s complete", binascii.hexlify(self.remote_addr).decode("utf-8"))
                self.keepalive_active = True
                self._keepaliveTimer()
            # connection complete - page timeout
            elif status == 4:
                log.info("Page timeout while connecting to %s", binascii.hexlify(self.remote_addr).decode("utf-8"))
        # disconnection complete event
        elif event == 5:
            self.handle = None
            log.info("Disconnected from " + binascii.hexlify(self.remote_addr).decode("utf-8"))
            if self.reconnect_counter < self.reconnect:
                log.info("Trying to reconnect (attempt %d of %d)", self.reconnect_counter,
                         self.reconnect)
                # wait a second, otherwise we sometimes don't get the connection complete event...
                time.sleep(1)
                self.connect()
                self.reconnect_counter += 1
        # authentication complete
        elif event == 6:
            # workaround as there is apparently a bug in pythons struct
            (status,) = struct.unpack_from("b", hci_data)
            (handle,) = struct.unpack_from("h", hci_data[1:])

            log.info("got Authentication Complete from handle %s, status: %d", hex(handle),
                     status)
            if status == 0:
                # authentication was successful, now set connection encryption
                self.core.sendHciCommand(0x0413, p16(handle) + "\x01")
                self.encrypted = True
                if self.encryption_callback:
                    self.encryption_callback()
                pass
            else:
                handle = 0
        # encryption change complete
        elif event == 8:
            (handle, encrypt) = struct.unpack_from("hb", hci_data)
            log.info("Got Encryption Change Complete from handle %s, encrypt: %d", hex(handle),
                     encrypt)
        # pin code request
        elif event == 0x16:
            (bd_addr,) = struct.unpack_from("6s", hci_data)
            log.info("Got Pin Code Request for %s", binascii.hexlify(bd_addr).decode("utf-8"))
            self.core.sendHciCommand(0x040d, bd_addr + "\x00" + "\x41" * 0x10)
        # link key request
        elif event == 0x17:
            (bd_addr,) = struct.unpack_from("6s", hci_data)
            log.info("Got Link Key request from %s", binascii.hexlify(bd_addr).decode("utf-8"))
            # link keys are not really implemented yet, just return a random link key
            self.core.sendHciCommand(0x040b, bd_addr + bytes.fromhex("0d2017c7f90a78cefeeed32210e6519a"))
            return

            if bd_addr in self.link_keys:
                # we have a link key for this device, set it
                lkey_buf = self.link_keys[bd_addr][::-1]
                self.core.sendHciCommand(0x040b, bd_addr + lkey_buf)
            else:
                # send negative link key reply, we don't have a key
                self.core.sendHciCommand(0x040c, bd_addr)

        # link key notification
        elif event == 0x18:
            (bd_addr, link_key) = struct.unpack_from("6s16s", hci_data)
            log.info("Got Link Key notification from %s, key: %s", bd_addr, binascii.hexlify(link_key).decode("utf-8"))
            self.link_keys[bd_addr] = link_key
        # io capability request
        elif event == 0x31:
            (bd_addr,) = struct.unpack_from("6s", hci_data)
            log.info("Got IO capability request from %s", binascii.hexlify(bd_addr).decode("utf-8"))
            # pretend to not have a display or oob data present
            # no display: 0x03, no oob: 0x00, auth requirements: 0x02
            self.core.sendHciCommand(0x042b, bd_addr + "\x03\x00\x02")
        # user confirmation request
        elif event == 0x33:
            (bd_addr,) = struct.unpack_from("6s", hci_data)
            log.info("Got user confirmation request from %s", binascii.hexlify(bd_addr).decode("utf-8"))
            # we just accept any confirmation requests
            self.core.sendHciCommand(0x42c, bd_addr)
        # simple pairing complete
        elif event == 0x36:
            (bd_addr,) = struct.unpack_from("6s", hci_data)
            log.info("Got simple pairing complete from %s", binascii.hexlify(bd_addr).decode("utf-8"))
        # le event
        # everything from le lands here...
        elif event == 0x3e:
            le_event_type = hci_data[0]
            le_handle = struct.unpack_from("h", hci_data[2:4])[0]
            # enhanced connection complete
            if le_event_type == 0x0a:
                log.info("Got le enhanced connection complete, removing device from whitelist")
                self.core.sendHciCommand(0x2012, bytes.fromhex("00") + self.remote_addr[::-1])
            elif le_event_type == 0x01:
                # sometimes we get connection complete events from previous sessions
                log.info("got le connection complete with handle %d", le_handle)
                if self.started_connection:
                    self.handle = le_handle
                else:
                    log.info("but ignoring it as we did not initiate this connection")

    def _aclEventHandler(self, data):
        log.debug("Received ACL data: %s", binascii.hexlify(data).decode("utf-8"))
        for handler in self.aclHandlers:
            handler(data)

    def encryptConnection(self):
        log.info("+ + + + + + + + Encrypt + + + + + + + +")
        if not self.handle:
            log.info("Cannot encrypt, no active connection")
            return

        # authentication requested hci cmd
        log.info("Send authentication requested hci cmd")
        self.core.sendHciCommand(0x0411, p8(self.handle) + "\x00")

        timeout = 3
        ctr = 0
        # wait 3 seconds for an encryted connection
        while ctr < timeout:
            time.sleep(0.1)
            if self.encrypted:
                return True

        return False

    def registerACLHandler(self, handler):
        self.aclHandlers.append(handler)
        log.debug("Registered new acl handler")

    def sendACL(self, data):
        data_len = p16(len(data))
        handle = p16(self.handle | 0x2000)
        log.debug("Sent acl data: %s", binascii.hexlify(data).decode("utf-8"))
        self.core.sendH4(0x02, handle + data_len + data)

    def connect(self):
        if self.connection_type == CONNECTION_TYPE_CLASSIC:
            self.core.connectToRemoteDevice(self.remote_addr)
        elif self.connection_type == CONNECTION_TYPE_BLE:
            # connection cancel
            self.core.sendHciCommand(0x200e, b"")
            # currently only supports random ble addresses, which are the ones
            # we're targeting here anyways
            self.core.connectToRemoteLEDevice(self.remote_addr, addr_type=0x01)
            self.started_connection = True
        else:
            log.error("invalid connection type: %d", self.connection_type)

        timeout_counter = 0
        while timeout_counter < self.timeout:
            if self.handle:
                break
            time.sleep(0.1)
            timeout_counter += 0.1

        if self.handle is None:
            status = False

            log.info("Connection timeout")
            if self.reconnect_counter < self.reconnect:
                log.info("Trying to reconnect (attempt %d of %d)", self.reconnect_counter,
                         self.reconnect)
                self.reconnect_counter += 1
                status = self.connect()
            else:
                log.error("Reconnection attempts exhausted")
                status = False
        else:
            log.info("Connection successful")
            if self.connection_callback:
                self.connection_callback()
            status = True

        return status
