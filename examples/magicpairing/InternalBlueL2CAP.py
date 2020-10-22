#!/usr/bin/python2

# Dennis Heinze

import binascii
import struct

from pwnlib import log

from internalblue.utils import p16


class L2CAPManager:
    def __init__(self, btconn, mtu=0x30):
        self.connection = btconn

        self.connection.registerACLHandler(self._receptionHandler)

        # cidHandlers is a map from CID -> function array
        self.cidHandlers = {}
        self.handlers = []
        self.mtu = mtu

    def sendData(self, data, cid):
        data_len = len(data)
        # if data_len > mtu
        log.debug("Sent L2CAP data to channel: %d, data: %s", cid, binascii.hexlify(data))
        self.connection.sendACL(p16(data_len) + p16(cid) + data)

    def registerHandler(self, handler):
        self.handlers.append(handler)
        log.debug("Registered L2CAP handler")

    def registerCIDHandler(self, handler, cid):
        if cid not in self.cidHandlers:
            self.cidHandlers[cid] = []

        self.cidHandlers[cid].append(handler)
        log.debug("Registered L2CAP handler for CID %d", cid)

    def _receptionHandler(self, data):
        if len(data) > 5:
            l2cap_data = data[5:]
        else:
            log.debug("Received invalid L2CAP data at handler: %s", data)
            return

        # prioritize specific CID handlers
        (length, cid) = struct.unpack_from("hh", l2cap_data)
        log.debug("Received L2CAP data for cid: %d, %s", cid, binascii.hexlify(l2cap_data))
        if cid in self.cidHandlers:
            for handler in self.cidHandlers[cid]:
                handler(l2cap_data[4:])

        for handler in self.handlers:
            handler(l2cap_data[4:])


class L2CAPSignalChannel:
    def __init__(self, chanman):
        self.chanman = chanman
        self.chanman.registerCIDHandler(0x01, self._receptionHandler)

    def sendCFrameRaw(self, code, identifier, length, data):
        self.chanman.sendData(code + identifier + length + data)

    def sendCFrame(self, code, identifier, data):
        data_len = len(data) / 2
        self.sendCFrameRaw(code, identifier, p16(data_len), data)

    def _receptionHandler(self, data):
        pass
