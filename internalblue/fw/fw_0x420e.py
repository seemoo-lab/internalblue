# fw_0x420e.py
#
# Generic firmware file in case we do not know something...
#
# Copyright (c) 2019 Jiska Classen. (MIT License)
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


class CYW20739B1(FirmwareDefinition):
    # Firmware Infos
    # Evaluation Kit CYW920719
    FW_NAME = "CYW20739B1 (NOT iPhone X/XR!)"
    # TODO this is not the iPhone firmware, we need to add a switch in fw.py

    # Device Infos
    DEVICE_NAME = (
        0x280CD0  # rm_deviceLocalName, FIXME has no longer a length byte prepended
    )
    BD_ADDR = 0x280CA4  # rm_deviceBDAddr

    # Heap
    BLOC_HEAD = 0x0200C7C  # g_dynamic_memory_GeneralUsePools
    BLOC_NG = True  # Next Generation Bloc Buffer

    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x001FFFFF, True, False),  # Internal ROM
        MemorySection(0x00200000, 0x0024FFFF, False, True),  # Internal Memory Cortex M3
        MemorySection(
            0x00270000, 0x0027FFFF, False, True
        ),  # Internal Memory Patchram Contents
        MemorySection(0x00280000, 0x00283FFF, False, True),  # ToRam
    ]

    # Patchram
    PATCHRAM_TARGET_TABLE_ADDRESS = Address(0x310000)
    PATCHRAM_ENABLED_BITMAP_ADDRESS = Address(0x310404)
    PATCHRAM_VALUE_TABLE_ADDRESS = Address(0x270000)
    PATCHRAM_NUMBER_OF_SLOTS = 256
    PATCHRAM_ALIGNED = False
    # only seems to work 4-byte aligned here ...

    # Assembler snippet for tracepoints
    # In contrast to the Nexus 5 patch, we uninstall ourselves automatically and use internal debug functions
    TRACEPOINT_BODY_ASM_LOCATION = 0x00223100
    TRACEPOINT_HOOKS_LOCATION = 0x00223200
    TRACEPOINT_HOOK_SIZE = 40
    TRACEPOINT_HOOK_ASM = """
            push {r0-r12, lr}       // save all registers on the stack (except sp and pc)
            ldr  r6, =0x%x          // addTracepoint() injects pc of original tracepoint here
            mov  r0, %d             // addTracepoint() injects the patchram slot of the hook patch
            bl   0x34964            // patch_uninstallPatchEntry(slot)
            bl   0x%x               // addTracepoint() injects TRACEPOINT_BODY_ASM_LOCATION here
            pop  {r0-r12, lr}       // restore registers
    
            // branch back to the original instruction
            b 0x%x                  // addTracepoint() injects the address of the tracepoint
    """

    TRACEPOINT_BODY_ASM_SNIPPET = """
            mov   r8, lr     // save link register in r8
    
            // dump registers like before
    
            // save status register in r5
            mrs  r5, cpsr
    
            // malloc HCI event buffer
            mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
            mov  r1, 76      // buffer size: size of registers (68 bytes) + type and length + 'TRACE_'
            bl   0xF7B6      // hci_allocateEventBlockWithLen(0xff, 78)
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
            bl   0xAF0BC     // memcpy(dst, src, len)
    
            // send HCI buffer to the host
            mov  r0, r4      // r4 still points to the beginning of the HCI buffer
            bl   0xF782      // hci_sendEvent
    
            // restore status register
            msr  cpsr_f, r5
    
            bl 0x2D702       // bthci_event_vs_DBFW_CoreDumpRAMImageEvent
    
            mov  lr, r8      // restore lr from r8
            bx   lr          // return
    
    """
