#!/usr/bin/python2

# Jiska Classen, Secure Mobile Networking Lab

import sys

from pwn import *
from internalblue.adbcore import ADBCore
import internalblue.hci as hci
import internalblue.cli as cli
import numpy as np




"""
Measure the RNG of the Nexus 5.
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

ASM_LOCATION_RNG = 0x211000  # load our snippet here
MEM_RNG = ASM_LOCATION_RNG + 0xf0  # store results here
MEM_ROUNDS = 0x1000  # run this often (x5 bytes) ... 0x1000 doesn't crash immediately but somewhen later :/
FUN_RNG = 0x0660ea  # original RNG function that we overwrite with bx lr
PRAND = 0x31FD48  # the pseudo random register we want to benchmark
# 0x318088  dc_nbtc_clk_adr
# 0x32A004  timer1value_adr
# 0x3186A0  dc_fhout_adr # lowest byte changes but doesnt look like rssi
# 0x31FC34  agcStatus_adr # constant
# 0x31FFA0  rxInitAngle_adr # lowest byte changes, rest is constant
# 0x31F8A4  spurFreqErr1_adr # also stays constant while establishing a connection, funny :D
# 0x31FD48  rxPskPhErr5_adr # same, constant during conn
# 0x200990  *mm_top TODO needs special memcpy but is only used once for init

ASM_SNIPPET_RNG = """

    // use r0-r7 locally
    push {r0-r7, lr}
    
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
    mov  r1, 6    // event length (+2)
    mov  r0, 0xff  // type: vendor specific
    bl   0x7AFC    // bthci_event_AllocateEventAndFillHeader
    mov  r4, r0    // save pointer to the buffer in r4

    // append buffer with "RAND"
    add  r0, 2  // buffer starts at 2 with data (?)
    ldr  r1, =0x444e4152 // RAND
    str  r1, [r0]
    add  r0, 4   // advance buffer by 4

    // send hci event
    mov  r0, r4  // back to buffer at offset 0
    bl  0x398c1     // send_hci_event_without_free()
    
    // free HCI buffer
    mov r0, r4
    bl  0x3FA36     // osapi_blockPoolFree

    pop   {r0-r4, pc}
    
    
""" % (MEM_ROUNDS, MEM_RNG, PRAND)


internalblue = ADBCore()
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

progress_log = log.info("installing assembly patches...")


# Install the RNG code in RAM
code = asm(ASM_SNIPPET_RNG, vma=ASM_LOCATION_RNG)
if not internalblue.writeMem(address=ASM_LOCATION_RNG, data=code, progress_log=progress_log):
    progress_log.critical("error!")
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



# read for multiple rounds to get more experiment data
rounds = 100
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


f = open("5_randomdata_pseudo-%irounds-reg0x%x.bin" % (rounds, PRAND), "wb")
f.write(data)
f.close()


#log.info("--------------------")
#log.info("Entering InternalBlue CLI to interpret RNG.")

## enter CLI
#cli.commandLoop(internalblue)

