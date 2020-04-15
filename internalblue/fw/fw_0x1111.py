#!/usr/bin/env python

# fw_0x1111.py
#
# Generic firmware file in case we do not know something...
#
# Copyright (c) 2020 The InternalBlue Team. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.

from __future__ import absolute_import
from .fw import MemorySection, FirmwareDefinition
from .. import Address


class BCM4375B1(FirmwareDefinition):
    # Firmware Infos
    # Samsung S10/S10e/S10+/S20
    FW_NAME = "BCM4375B1"


    # Device Infos
    DEVICE_NAME = 0x207F2A
    BD_ADDR = 0x2026E2


    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x0013FFFF, True, False),  # Internal ROM
        MemorySection(0x00160000, 0x0017FFFF, False, True),  # Patches
        MemorySection(0x00200000, 0x00288000, False, True),  # Internal Memory Cortex M3
        MemorySection(0x00300000, 0x0037FFFF, False, True),
    ]

    # Patchram
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310404
    PATCHRAM_VALUE_TABLE_ADDRESS = 0x160000
    PATCHRAM_NUMBER_OF_SLOTS = 256
    PATCHRAM_ALIGNED = False

    BLOC_HEAD = 0x20075C
    BLOC_NG = True

    # Enable enhanced advertisement reports (bEnhancedAdvReport)
    # tested but by default the S10 only uses the LE Extended format, which is different...
    ENHANCED_ADV_REPORT_ADDRESS = Address(0x20D176)

    # Assembler snippet for tracepoints
    # In contrast to the Nexus 5 patch, we uninstall ourselves automatically and use internal debug functions
    # TODO S10e does no longer have a patch uninstall function... writemem works to remove patches, but copying
    #      Assembly of the original function from an eval board does not work...
    # TRACEPOINT_BODY_ASM_LOCATION = 0x00218300
    # TRACEPOINT_HOOKS_LOCATION = 0x00218500
    # TRACEPOINT_HOOK_SIZE = 40
    TRACEPOINT_HOOK_ASM = """
            push {r0-r12, lr}       // save all registers on the stack (except sp and pc)
            ldr  r6, =0x%x          // addTracepoint() injects pc of original tracepoint here
            mov  r9, %d             // addTracepoint() injects the patchram slot of the hook patch
            bl   0x%x               // addTracepoint() injects TRACEPOINT_BODY_ASM_LOCATION here
            pop  {r0-r12, lr}       // restore registers
    
            // branch back to the original instruction
            b 0x%x                  // addTracepoint() injects the address of the tracepoint
    """

    TRACEPOINT_BODY_ASM_SNIPPET = """
    
            mov   r8, lr     // save link register in r8
           
            b delete_slot
    
            // dump registers like before
    
            // save status register in r5
            mrs  r5, cpsr
    
            // malloc HCI event buffer
            mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
            mov  r1, 76      // buffer size: size of registers (68 bytes) + type and length + 'TRACE_'
            bl   0x6cfe2     // hci_allocateEventBlockWithLen(0xff, 78) #DONE
            mov  r4, r0      // save pointer to the buffer in r4
    
            // append our custom header (the word 'TRACE_') after the event code and event length field
            add  r0, 2            // write after the length field
            ldr  r1, =0x43415254  // 'TRAC'
            str  r1, [r0]
            add  r0, 4            // advance the pointer.
            ldr  r1, =0x5f45      // 'E_'
            strh r1, [r0]
            add  r0, 2            // advance the pointer. r0 now points to the start of the register values
    
            // store pc
            str  r6, [r0]    // r6 still contains the address of the original pc
            add  r0, 4       // advance the pointer.
    
            // store sp
            mov  r1, 56      // 14 saved registers * 4
            add  r1, sp
            str  r1, [r0]
            add  r0, 4       // advance the pointer.
    
            // store status register
            str  r5, [r0]
            add  r0, 4       // advance the pointer.
    
            // store other registers
            mov  r1, sp
            mov  r2, 56
            bl   0x2774      // memcpy(dst, src, len) #DONE
    
            // send HCI buffer to the host
            mov  r0, r4      // r4 still points to the beginning of the HCI buffer
            bl   0x6cfa8     // hci_sendEvent #DONE
    
            // restore status register
            msr  cpsr_f, r5
            
            bl 0x6af24       // bthci_event_vs_DBFW_CoreDumpRAMImageEvent #DONE
    
            // not possible... could not find patch_uninstallPatchEntry(slot) 
            // -> disable TP by hand, we stored in r9
            // TODO - does not work??
            delete_slot:
            mov r0, #0
            mov   r1, r0
            lsl   r0, r0, #0x2
            ldr   r3, =0x00310404
            sub.w r0, r0, #0x400
            add   r3, #0x3c
            add   r0, r3
            movw  r2, #0xffff
            str   r2, [r0, #0x0]
            ldr   r0,=0x00310404
            add   r0, #0x2c
            ldr   r2, [r0,#0x0]
            mov   r3, #0x1
            lsl   r3, r1
            bic   r2, r3
            str   r2, [r0, #0x0]
    
            
            mov  lr, r8      // restore lr from r8
            bx   lr          // return
    
        .align
        patchram:
        .byte 0x04
        .byte 0x04
        .byte 0x31
        .byte 0x00
    
    """
