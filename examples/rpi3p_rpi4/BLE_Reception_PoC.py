#!/usr/bin/env python2

# Jiska Classen

# Get receive statistics on a Raspberry Pi 3 for BLE connection events

from pwn import *
from internalblue.hcicore import HCICore


internalblue = HCICore()
device_list = internalblue.device_list()
if len(device_list) == 0:
    log.warn("No HCI devices connected!")
    exit(-1)
internalblue.interface = device_list[0][1] # just use the first device


RX_DONE_HOOK_ADDRESS = 0x56622  # _connTaskRxDone
HOOKS_LOCATION = 0x210500
ASM_HOOKS = """

    // restore first 4 bytes of _connTaskRxDone
    push  {r4-r6,lr}
    mov   r4, r0

    // fix registers for our own routine
    push  {r1-r7, lr}
    mov   r7, r0

    // allocate vendor specific hci event
    mov  r2, 243
    mov  r1, 0xff
    mov  r0, 245
    bl   0x2770  // bthci_event_AllocateEventAndFillHeader(4+239+2, 0xff, 4+239);
    mov  r4, r0  // save pointer to the buffer in r4

    // append buffer with "RXDN"
    add  r0, 10  // buffer starts at 10 with data
    ldr  r1, =0x4e445852 // RXDN
    str  r1, [r0]
    add  r0, 4   // advance buffer by 4

    // copy 239 bytes of le_conn to buffer
    mov  r2, #238
    mov  r1, r7  // le_conn[0]
    bl   0x775C8 // __rt_memcpy

    // for debugging purposes, we overwrite the first byte
    // (which is the connTaskCallback anyway) with RSSI info
    mov  r2, #1  // 1 rssi byte
    add.w r1, r7, #0x10a // le_conn[0x10a] is position of rssi
    mov  r0, r4
    add  r0, 14
    bl   0x775C8 // __rt_memcpy

    // send hci event
    mov  r0, r4  // back to buffer at offset 0
    bl   0x268E  // send_hci_event

    // undo registers for our own routine
    mov   r0, r7
    pop   {r1-r7, lr}

    // branch back to _connTaskRxDone + 4
    b     0x56626

"""

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

# Install hooks
code = asm(ASM_HOOKS, vma=HOOKS_LOCATION)
log.info("Writing hooks to 0x%x..." % HOOKS_LOCATION)
if not internalblue.writeMem(HOOKS_LOCATION, code):
    log.critical("Cannot write hooks at 0x%x" % HOOKS_LOCATION)
    exit(-1)

log.info("Installing hook patch...")
patch = asm("b 0x%x" % HOOKS_LOCATION, vma=RX_DONE_HOOK_ADDRESS)
if not internalblue.patchRom(RX_DONE_HOOK_ADDRESS, patch):
    log.critical("Installing patch for _connTaskRxDone failed!")
    exit(-1)


log.info("--------------------")
log.info("To see statistics, execute 'internalblue' and run 'log_level debug'.")