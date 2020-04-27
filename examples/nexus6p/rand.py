#!/usr/bin/python2

# Jiska Classen, Secure Mobile Networking Lab

import sys

from pwn import *
from internalblue.adbcore import ADBCore
import internalblue.hci as hci
import internalblue.cli as cli
import numpy as np
from datetime import datetime



"""
Measure the RNG of the Nexus 6.
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

* Launch_RAM patch, as Launch_RAM works but only with a 1.3 second
  break. So we overwrite it as in the evaluation boards.

"""

ASM_LOCATION_RNG = 0x21F000  # load our snippet here
MEM_RNG = ASM_LOCATION_RNG + 0xf0  # store results here
MEM_ROUNDS = 0x1000  # run this often (x5 bytes) ... 0x1000 doesn't crash immediately but somewhen later :/
FUN_RNG = 0x55FD6  # original RNG function that we overwrite with bx lr

ASM_SNIPPET_RNG = """

    // use r0-r7 locally
    push {r0-r7, lr}
    
    // send a command complete event as we overwrote the launch_RAM handler to prevent HCI timeout event wait
    mov  r0, #0xFC4E // launch RAM command
    mov  r1, 0       // event success
    bl   0x229C      // bthci_event_SendCommandCompleteEventWithStatus
    
    // enter RNG dumping mode
    ldr  r0, =0x%x      // run this many rounds
    ldr  r1, =0x%x      // dst: store RNG data here
    bl   dump_rng
    
    // done, let's notify
    bl   notify_hci
    
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
    mov  r2, 4     // event length
    mov  r0, 6     // event length (+2)
    mov  r1, 0xff  // type: vendor specific
    bl   0x22C4    // malloc_hci_event_buffer
    mov  r4, r0    // save pointer to the buffer in r4

    // append buffer with "RAND"
    add  r0, 10  // buffer starts at 10 with data
    ldr  r1, =0x444e4152 // RAND
    str  r1, [r0]
    add  r0, 4   // advance buffer by 4

    // send hci event
    mov  r0, r4  // back to buffer at offset 0
    bl  0x20F4     // send_hci_event()

    pop   {r0-r4, pc}
    
    
""" % (MEM_ROUNDS, MEM_RNG)


internalblue = ADBCore(log_level='info')
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

progress_log = log.info("installing assembly patches to crash other device on connect requests...")


# Install the RNG code in RAM
code = asm(ASM_SNIPPET_RNG, vma=ASM_LOCATION_RNG)
if not internalblue.writeMem(address=ASM_LOCATION_RNG, data=code, progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)

# Nexus 6P Launch_RAM fix: overwrite an unused HCI handler
# Here it is not called within the handler table but within another function.
patch = asm("b 0x%x" % ASM_LOCATION_RNG, vma=0x59042)
if not internalblue.patchRom(0x59042, patch):
    log.critical("Could not implement our launch RAM fix!")
    exit(-1)

# Disable original RNG
patch = asm("bx lr; bx lr", vma=FUN_RNG)  # 2 times bx lr is 4 bytes and we can only patch 4 bytes
if not internalblue.patchRom(FUN_RNG, patch):
    log.critical("Could not disable original RNG!")
    exit(-1)



log.info("Installed all RNG hooks.")

adb.process(["su", "-c", "svc wifi disable"])

log.info("Disabled Wi-Fi core.")




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
        log.debug("Random data done!")
        internalblue.rnd_done = True

# add RNG callback
internalblue.registerHciCallback(rngStatusCallback)


# enter CLI
#cli.commandLoop(internalblue)



# read for multiple rounds to get more experiment data
rounds = 1000
i = 0
data = bytearray()
while rounds > i:
    log.info("RNG round %i..." % i)

    # launch assembly snippet
    internalblue.launchRam(ASM_LOCATION_RNG)

    # wait until we set the global variable that everything is done
    while not internalblue.rnd_done:
        continue
    internalblue.rnd_done = False

    # sleep(1.3)  # Nexus 6P specific HCI bugfix! Launch_RAM doesn't like HCI...
    # 8s is safe, 2s did also work 1k times, 1s aborted after 406 and 403.
    # 1.3s was also safe.

    # and now read and save the random
    random = internalblue.readMem(MEM_RNG, MEM_ROUNDS*5)
    data.extend(random)

    i = i + 1

log.info("Finished acquiring random data!")

# every 5th byte i 0x42
check = data[4::5]
for c in check:
    if c != 0x42:
        log.error("Data was corrupted by another process!")

# uhm and for deleting every 5th let's take numpy (oh why??)
data = np.delete(data, np.arange(4, data.__len__(), 5))


f = open("6p_randomdata-%irounds-%s.bin" % (rounds, datetime.now()), "wb")
f.write(data)
f.close()


#log.info("--------------------")
#log.info("Entering InternalBlue CLI to interpret RNG.")

## enter CLI
#cli.commandLoop(internalblue)

