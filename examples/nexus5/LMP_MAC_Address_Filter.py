#!/usr/bin/env python3

# Jiska Classen, Secure Mobile Networking Lab
from internalblue import Address
from internalblue.adbcore import ADBCore
from internalblue.utils.pwnlib_wrapper import log, asm
from binascii import unhexlify
"""
Filter connections by MAC address before entering LMP dispatcher.
Enter MAC addresses you trust into whitelist.

"""
WHITELIST = ["aabbccddeeff", "133713371337", "affedeadbeef"]

WHITELIST_BYTES = unhexlify(''.join(WHITELIST))[::-1]  # change mac addr byte order
HOOK_LMP_FILTER = Address(0x3f3f4)               # This function is in ROM
ASM_LOCATION_LMP_FILTER = 0x00211900    # 0xD5900
ASM_SNIPPET_LMP_FILTER = """
b lmp_dispatcher_filter

lmp_dispatcher_filter:
    push {r2-r8, lr}        // the patche's branch overwrote the original function's push
    
    // continue similar to original function to get the connection struct
    ldr  r7, =0x200478
    ldrh r0, [r0, 2]
    ldr  r1, [r7, 0x4] 
    ldrb r1, [r1, 0xc]
    lsrs r6, r1, 1          // LMP opcode
    bl   0x42c04            // get_ptr_to_connection_struct_from_index_42C04, r0=conn_struct

    ldr  r1, =whitelist
    mov  r2, 0              // whitelist index

    mov  r3, 0              // MAC address pointer
    whitelist_loop:
        ldrb r5, [r1, 0x1]
        ldrb r4, [r0, 0x28] // BD_ADDR = connection[0x28:0x2E][::-1]
        cmp  r4, r5
        bne mac_invalid        

        adds r3, 1
        adds r0, 1
        adds r1, 1
        
        //check if we finished a MAC address
        cmp  r3, 6
        bne  whitelist_loop
    
    mac_valid:
        // undo loop iteration on connection struct
        subs r0, r3
        
        // return to original logic
        b    0x3f406
    
    // called when one MAC is invalid in the list, go to next element 
    mac_invalid:
        // undo loop on connection struct (we moved the pointer to the
        // connection struct itself to move on mac bytes)
        subs r0, r3
        
        adds r2, 1              // number of next element in list
        ldr  r1, =whitelist
        ldrb r3, [r1, 0x0]      // compare with actual list length
        cmp  r2, r3
        beq  all_macs_invalid   // last element reached in list and it was invalid
        
        
        //set r1 to whitelist+6*r2 (next MAC address)
        mov  r3, 6
        muls r3, r2
        ldr  r1, =whitelist
        adds r1, r3

        // start with next iteration of whitelist loop
        mov r3, 0          
        b whitelist_loop

    // action performed if nothing in the list matched...
    // this one does a lmp_not_accepted, works for us to prevent parsing
    all_macs_invalid:
        // assume we have an lmp error that we can handle ourselves...
        mov  r4, r0
        b    0x3f46c
    
    whitelist:
        .byte 0x%02x //length
        //mac address list        
        %s   
    
""" % (len(WHITELIST), ''.join([".byte 0x%02x\n" % ord(x) for x in WHITELIST_BYTES]))

internalblue = ADBCore()
internalblue.interface = internalblue.device_list()[0][1] # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

progress_log = log.info("Writing ASM snippet for LMP MAC address filter.")
code = asm(ASM_SNIPPET_LMP_FILTER, vma=ASM_LOCATION_LMP_FILTER)
if not internalblue.writeMem(address=ASM_LOCATION_LMP_FILTER, data=code, progress_log=progress_log):
    progress_log.critical("error!")
    exit(-1)

# all send_lmp functions are in rom...
log.info("Installing MAC address filter hook patch...")
patch = asm("b 0x%x" % ASM_LOCATION_LMP_FILTER, vma=HOOK_LMP_FILTER)
if not internalblue.patchRom(HOOK_LMP_FILTER, patch):
    log.critical("error!")
    exit(-1)

# shutdown connection
internalblue.shutdown()
log.info("Goodbye")
