#!/usr/bin/python3

# Jiska Classen, Secure Mobile Networking Lab

import sys
import binascii
from argparse import Namespace
from datetime import datetime

import numpy as np
from pwnlib.asm import asm

import internalblue.hci as hci
from internalblue.cli import InternalBlueCLI
from internalblue.hcicore import HCICore
from internalblue.utils.packing import p32

"""
Measure the RNG of the CYW20819 Evaluation Board.
Similar to matedealer's thesis, p. 51.

Changes:

* Every 5th byte is now 0x42 to ensure that no other process wrote
  into this memory region in the meantime. Does it job and cheaper
  than checksums.

* When we are done, we send an HCI event containing 'RAND'. We catch
  this with a callback. Way more efficient than polling.

* We overwrite the original `rbg_rand` function with `bx lr` to
  ensure we're the only ones accessing the RNG.
  
* BT only, no need to disable Wi-Fi.

* CYW20819-specific patch: Launch_RAM crashes the chip, so we build
  our own HCI handler.

"""

# ASM_LOCATION_RNG = 0x271000  # load our snippet into Patchram (we need to disable all patches for this!)
ASM_LOCATION_RNG = 0x219000
# 0x219000 crashed with 0x1000 in round 27
# 0x216000 looks emptier but crashed on first attempt
# memdump doesn't look so good in binwalk entropy, so we really don't have memory I fear
MEM_RNG = ASM_LOCATION_RNG + 0xf0  # store results here
MEM_ROUNDS = 0x100  # run this often (x5 bytes) .. worked with 0x500 in one run but then didn't in another
# longer snippets (0x600) don't work! 0x500 works but is corrupted by other process.
FUN_RNG = 0xB2562  # original RNG function that we overwrite with bx lr
PRAND = 0x3186A0  # the pseudo random register we want to benchmark
# !!! also uses either cache or HRNG even though the first check failed, and then the following 4 registers
# 0x318088  dc_nbtc_clk_adr
# 0x32A004  timer1value_adr
# 0x3186A0  dc_fhout_adr
# 0x410434  agcStatus_adr

ASM_SNIPPET_RNG = """

    // use r0-r7 locally
    push {r0-r7, lr}
    
    // send a command complete event as we overwrote the launch_RAM handler to prevent HCI timeout event wait
    mov  r0, #0xFC4E // launch RAM command
    mov  r1, 0       // event success
    bl   0x1179E     // bthci_event_SendCommandCompleteEventWithStatus
    
    
    // enter RNG dumping mode
    ldr  r0, =0x%x      // run this many rounds
    ldr  r1, =0x%x      // dst: store RNG data here
    bl   dump_pseudo
    
    // done, let's notify
    bl   notify_hci
    
    // back to lr
    pop  {r0-r7, pc}
    
    
    //// the main RNG dumping routine
    dump_pseudo:

    // dst is in r1, dump RNG value here
    ldr  r2, =0x%x
    ldr  r3, [r2]
    str  r3, [r1]
    add  r1, 4 
    
    // add a test byte to ensure that no other process wrote here
    mov  r3, 0x42
    str  r3, [r1]
    add  r1, 1
    
    // loop for rounds in r0
    subs r0, 1
    bne  dump_pseudo
    bx   lr
    
    
    
    //// issue an HCI event once we're done
    notify_hci:
        
    push  {r0-r4, lr}

    // allocate vendor specific hci event
    mov  r2, 243
    mov  r1, 0xff
    mov  r0, 245
    bl   0x117CA    // bthci_event_AllocateEventAndFillHeader
    mov  r4, r0     // save pointer to the buffer in r4

    // append buffer with "RAND"
    add  r0, 10  // buffer starts at 10 with data
    ldr  r1, =0x444e4152 // RAND
    str  r1, [r0]
    add  r0, 4      // advance buffer by 4

    // send hci event
    mov  r0, r4     // back to buffer at offset 0
    bl   0x1156E    // bthci_event_AttemptToEnqueueEventToTransport
    
    
    pop   {r0-r4, pc}
    
    
""" % (MEM_ROUNDS, MEM_RNG, PRAND)

internalblue = HCICore()
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    internalblue.logger.critical("No connection to target device.")
    exit(-1)

internalblue.logger.info("Installing assembly patches...")

# Disable Patchram
# if not internalblue.writeMem(address=0x310404, data=b'\x00\x00\x00\x00\x00', progress_log=None):
#    internalblue.logger.critical("error!")
#    exit(-1)

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

# CYW20819 Launch_RAM fix: overwrite an unused HCI handler
# The Launch_RAM handler is broken so we can just overwrite it to call the function we need.
# The handler table entry for it is at 0xF2884, and it points to launch_RAM+1.
if not internalblue.patchRom(0xF2884, p32(ASM_LOCATION_RNG + 1)):  # 0x219001
    internalblue.logger.critical("Could not implement our launch RAM fix!")
    exit(-1)

# Disable functions that crash us when using the target memory region at 0x219000
patch = asm("bx lr; bx lr", vma=0x79AC6)  # 2 times bx lr is 4 bytes and we can only patch 4 bytes
if not internalblue.patchRom(0x79AC6, patch):
    internalblue.logger.critical("Could not disable original bcs_taskDeactivate_blocking!")
    exit(-1)

internalblue.logger.info("Installed all RNG hooks.")

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

    if hcipkt.data[0:4] == bytes("RAND", "utf-8"):
        internalblue.logger.debug("Random data done!")
        internalblue.rnd_done = True


# add RNG callback
internalblue.registerHciCallback(rngStatusCallback)

# read for multiple rounds to get more experiment data
rounds = 1000
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

    # do an immediate check to tell where the corruption happened
    check = random[4::5]
    pos = 0
    failed = False
    for c in check:
        pos = pos + 1
        if c != 0x42:
            internalblue.logger.warning("    Data was corrupted at 0x%x, repeating round." % (MEM_RNG + (pos * 5)))
            failed = True
            break

    if failed:
        continue

    # no errors, save data
    data.extend(random)
    i = i + 1

    # print the data as a demo
    random = np.delete(random, np.arange(4, random.__len__(), 5))
    randstring = binascii.hexlify(bytearray(random))
    internalblue.logger.info([randstring[i:i + 8] for i in range(0, len(randstring), 8)])

internalblue.logger.info("Finished acquiring random data!")

# uhm and for deleting every 5th let's take numpy (oh why??)
data = np.delete(data, np.arange(4, data.__len__(), 5))

f = open("cyw20819-randomdata_pseudo-0x500-%irounds-reg%x-%s.bin" % (rounds, PRAND, datetime.now()), "wb")
f.write(data)
f.close()

internalblue.logger.info("--------------------")
internalblue.logger.info("Entering InternalBlue CLI to interpret RNG.")

# enter CLI
cli = InternalBlueCLI(Namespace(data_directory=None, verbose=False, trace=None, save=None), internalblue)
sys.exit(cli.cmdloop())
