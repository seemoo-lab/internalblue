#!/usr/bin/env python2

# Jiska Classen

# Get receive statistics on a Nexus 5 for BLE connection events

from pwn import *
from internalblue.adbcore import ADBCore
import internalblue.hci as hci
import internalblue.cli as cli

internalblue = ADBCore(serial=False)
device_list = internalblue.device_list()
if len(device_list) == 0:
    log.warn("No HCI devices connected!")
    exit(-1)
internalblue.interface = device_list[0][1] # just use the first device



"""
# _connTaskRxDone has a Patchram position, Nexus 5 patches look so worse that I guess
# they never planned to support BLE. Even callbacks are defined in Patchram.
# You need to adjust the RX_DONE_HOOK_ADDRESS in the beginning.
"""
RX_DONE_HOOK_ADDRESS = 0x224DEA
HOOKS_LOCATION = 0xd7500
ASM_HOOKS = """

    // restore first 4 bytes of _connTaskRxDone
    push  {r4-r8,lr}
    mov   r4, r0

    // fix registers for our own routine
    push  {r1-r7, lr}
    mov   r7, r0

    // allocate vendor specific hci event
    mov  r2, 243
    mov  r1, 0xff
    mov  r0, 245
    bl   0x7AFC  // bthci_event_AllocateEventAndFillHeader(4+239+2, 0xff, 4+239);
    mov  r4, r0  // save pointer to the buffer in r4

    // append buffer with "RXDN"
    add  r0, 2  // buffer starts at 2 with data (?)
    ldr  r1, =0x4e445852 // RXDN
    str  r1, [r0]
    add  r0, 4   // advance buffer by 4

    // copy 239 bytes of le_conn to buffer
    mov  r2, #238
    mov  r1, r7  // le_conn[0]
    //add  r1, 0x100 //TODO use this to access the connection struct with different offset
    bl   0x46FE6 // __rt_memcpy

    // for debugging purposes, we overwrite the first byte
    // (which is the connTaskCallback anyway) with RSSI info
    mov  r2, #1  // 1 rssi byte
    add.w r1, r7, #0x12c // le_conn[0x12c] is position of RSSI in Nexus 5
    mov  r0, r4
    add  r0, 6
    bl   0x46FE6  // __rt_memcpy

    // send hci event
    mov  r0, r4  // back to buffer at offset 0
    bl  0x398c1     // send_hci_event_without_free()
    
    // free HCI buffer
    mov r0, r4
    bl  0x3FA36     // osapi_blockPoolFree

    // undo registers for our own routine
    mov   r0, r7
    pop   {r1-r7, lr}

    // branch back to _connTaskRxDone + 4
    b 0x%x

""" % (RX_DONE_HOOK_ADDRESS+4)

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
if not internalblue.writeMem(RX_DONE_HOOK_ADDRESS, patch):
    log.critical("Installing patch for _connTaskRxDone failed!")
    exit(-1)


# RXDN statistics callback variables
internalblue.last_nesn_sn = None
internalblue.last_success_event = None


def lereceiveStatusCallback(record):
    """
    RXDN Callback Function

    Depends on the raspi3_rxdn.py or eval_rxdn.py script,
    which patches the _connTaskRxDone() function and copies
    info from the LE connection struct to HCI.
    """

    hcipkt = record[0]  # get HCI Event packet

    if not issubclass(hcipkt.__class__, hci.HCI_Event):
        return

    if hcipkt.data[0:4] == "RXDN":
        data = hcipkt.data[4:]

        # Raspi 3 gets errors
        if len(data) < 239:
            return

        # !!! Nexus 5 has really outdated struct...
        packet_curr_nesn_sn = u8(data[0xa0])
        packet_channel_map = data[0x4c:0x4c+38]
        packet_channel = u8(data[0x7b])
        packet_event_ctr = u16(data[0x86:0x88])
        packet_rssi = u8(data[0])

        if internalblue.last_nesn_sn and ((internalblue.last_nesn_sn ^ packet_curr_nesn_sn) & 0b1100) != 0b1100:
            log.info("             ^----------------------------- ERROR --------------------------------")

        # currently only supported by eval board: check if we also went into the process payload routine,
        # which probably corresponds to a correct CRC
        # if self.last_success_event and (self.last_success_event + 1) != packet_event_ctr:
        #    log.debug("             ^----------------------------- MISSED -------------------------------")

        # TODO example for setting the channel map
        # timeout needs to be zero, because we are already in an event reception routine!
        # self.sendHciCommand(0x2014, '\x00\x00\xff\x00\x00', timeout=0)

        internalblue.last_nesn_sn = packet_curr_nesn_sn

        # draw channel with rssi color
        color = '\033[92m'  # green
        if 0xc8 > packet_rssi >= 0xc0:
            color = '\033[93m'  # yellow
        elif packet_rssi < 0xc0:
            color = '\033[91m'  # red

        channels_total = u8(packet_channel_map[37])
        channel_map = 0x0000000000
        if channels_total <= 37:  # raspi 3 messes up with this during blacklisting
            for channel in range(0, channels_total):
                channel_map |= (0b1 << 39) >> u8(packet_channel_map[channel])

        log.info("LE event %5d, map %10x, RSSI %d: %s%s*\033[0m " % (packet_event_ctr, channel_map,
                                                                      (packet_rssi & 0x7f) - (128 * (packet_rssi >> 7)),
                                                                      color, ' ' * packet_channel))



log.info("--------------------")
log.info("Entering InternalBlue CLI to display statistics.")

# add RXDN callback
internalblue.registerHciCallback(lereceiveStatusCallback)


# enter CLI
cli.commandLoop(internalblue)