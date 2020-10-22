#!/usr/bin/python2

# Jiska Classen, Secure Mobile Networking Lab

import os
import sys
from argparse import Namespace

import numpy as np
from pwnlib.asm import asm

import internalblue.hci as hci
from internalblue.cli import InternalBlueCLI
from internalblue.hcicore import HCICore

"""
Measure the RNG of the Raspberry Pi 3.
Similar to matedealer's thesis, p. 51.

Changes:

* Every 5th byte is now 0x42 to ensure that no other process wrote
  into this memory region in the meantime. Does it job and cheaper
  than checksums.

* When we are done, we send an HCI event containing 'RAND'. We catch
  this with a callback. Way more efficient than polling.

* We overwrite the original `rbg_rand` function with `bx lr` to
  ensure we're the only ones accessing the RNG.
  
* Disable Wi-Fi as the RNG might be shared.

"""

ASM_LOCATION_RNG = 0x21f000  # load our snippet here, yes we have space :) 
MEM_RNG = ASM_LOCATION_RNG + 0xf0  # store results here
MEM_ROUNDS = 0x1000  # run this often (x5 bytes)
FUN_RNG = 0x6672A  # original RNG function that we overwrite with bx lr

ASM_SNIPPET_RNG = """

    // use r0-r7 locally
    push {r0-r7, lr}
    
    // enter RNG dumping mode
    ldr  r0, =0x%x      // run this many rounds
    ldr  r1, =0x%x      // dst: store RNG data here
    bl   dump_rng
    
    // done, let's notify
    //bl   notify_hci
    mov  r0, 0
    mov  r1, 0
    mov  r2, 0
    mov  r3, 0
    bl   0x1a14 //ok whatever this one produces 2e0000000000000000000000000000000000000000 
    
    // back to lr
    pop  {r0-r7, pc}
    
    
    //// the main RNG dumping routine
    dump_rng:
    
    // wait until RNG is ready, which is indicated by status 0x200fffff
    wait_ready:
        ldr  r2,=0x314008
        ldr  r2, [r2]
        ldr  r3, =0x200fffff
        cmp  r2, r3
        bne  wait_ready  
    
    // request new entropy: 0x314004=1
    mov  r3, 1
    ldr  r2, =0x314004
    str  r3, [r2]
    
    // dst is in r1, dump RNG value here
    ldr  r2, =0x31400c
    ldr  r3, [r2]
    str  r3, [r1]
    add  r1, 4 
    
    // add a test byte to ensure that no other process wrote here
    mov  r3, 0x42
    str  r3, [r1]
    add  r1, 1
    
    // loop for rounds in r0
    subs r0, 1
    bne  dump_rng
    bx   lr
    
    
    
    //// issue an HCI event once we're done
    notify_hci:
        
    push  {r0-r4, lr}

    // allocate vendor specific hci event
    mov  r2, 10     // event length
    mov  r0, 12     // event length (+2)
    mov  r1, 0xff  // type: vendor specific
    bl   0x2770    // bthci_event_AllocateEventAndFillHeader (the r0+r2 variant)
    mov  r4, r0    // save pointer to the buffer in r4

    // append buffer with "RAND"
    add  r0, 2  // buffer starts at 2 with data (?)
    ldr  r1, =0x444e4152 // RAND
    str  r1, [r0]
    add  r0, 4   // advance buffer by 4

    // send hci event
    mov  r0, r4  // back to buffer at offset 0

    pop   {r0-r4, lr}
    b     0x268E     // send_hci_event_without_free()
    
    
""" % (MEM_ROUNDS, MEM_RNG)

internalblue = HCICore()
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    internalblue.logger.critical("No connection to target device.")
    exit(-1)

internalblue.logger.info("installing assembly patches...")

# Install the RNG code in RAM
code = asm(ASM_SNIPPET_RNG, vma=ASM_LOCATION_RNG)
if not internalblue.writeMem(address=ASM_LOCATION_RNG, data=code, progress_log=None):
    internalblue.logger.critical("error!")
    exit(-1)

# Disable original RNG
patch = asm("bx lr; bx lr", vma=FUN_RNG)  # 2 times bx lr is 4 bytes and we can only patch 4 bytes
if not internalblue.patchRom(FUN_RNG, patch):
    internalblue.logger.critical("Could not disable original RNG!")
    exit(-1)

internalblue.logger.info("Installed all RNG hooks.")
os.system("sudo rfkill block wifi")
internalblue.logger.info("Disabled Wi-Fi core.")

"""
We cannot call HCI Read_RAM from this callback as it requires another callback (something goes wrong here),
so we cannot solve this recursively but need some global status variable. Still, polling this is way faster
than polling a status register in the Bluetooth firmware itself.
"""
# global status
internalblue.rnd_done = False


def rngStatusCallback(record):
    hcipkt = record[0]  # get HCI Event packet

    if not issubclass(hcipkt.__class__, hci.HCI_Event):
        return

    if hcipkt.data[0:21] == b'\x2e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        internalblue.logger.debug("Random data done!")
        internalblue.rnd_done = True


# add RNG callback
internalblue.registerHciCallback(rngStatusCallback)


# read for multiple rounds to get more experiment data
rounds = 100
i = 0
data = bytearray()
while rounds > i:
    internalblue.logger.info("RNG round %i..." % i)

    # launch assembly snippet
    internalblue.launchRam(ASM_LOCATION_RNG)

    # wait until we set the global variable that everything is done
    while not internalblue.rnd_done:
        continue
    internalblue.rnd_done = False

    # and now read and save the random
    random = internalblue.readMem(MEM_RNG, MEM_ROUNDS * 5)
    data.extend(random)

    i = i + 1

internalblue.logger.info("Finished acquiring random data!")

# every 5th byte i 0x42
check = data[4::5]
for c in check:
    if c != 0x42:
        internalblue.logger.error("Data was corrupted by another process!")

# uhm and for deleting every 5th let's take numpy (oh why??)
data = np.delete(data, np.arange(4, data.__len__(), 5))

f = open("rpi3p-randomdata-%irounds.bin" % rounds, "wb")
f.write(data)
f.close()

internalblue.logger.info("--------------------")
internalblue.logger.info("Entering InternalBlue CLI to interpret RNG.")

# enter CLI
cli = InternalBlueCLI(Namespace(data_directory=None, verbose=False, trace=None, save=None), internalblue)
sys.exit(cli.cmdloop())
