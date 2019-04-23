# fw_default.py
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

from fw import MemorySection

# Firmware Infos
# Evaluation Kit CYW927035
FW_NAME = "CYW27035B1"

# Device Infos
DEVICE_NAME = 0x280CD0                  # rm_deviceLocalName, FIXME has no longer a length byte prepended
BD_ADDR = 0x280CA4                      # rm_deviceBDAddr

#Heap
BLOC_HEAD = 0x200474
BLOC_NG = True                          # Next Generation Bloc Buffer

# Memory Sections
#                          start,    end,           is_rom? is_ram?
SECTIONS = [ MemorySection(0x00000000, 0x001fffff,  True,  False),  # Internal ROM
             MemorySection(0x00200000, 0x0024ffff,  False, True),   # Internal Memory Cortex M3
             MemorySection(0x00270000, 0x0027ffff,  False, True),   # Internal Memory Patchram Contents
             MemorySection(0x00280000, 0x00283fff,  False, True),   # ToRam
             MemorySection(0x00300000, 0x00307fff,  False, True),   # HW Regs Cortex M3 (readable)
             MemorySection(0x00310000, 0x00321fff,  False, True),   # HW Regs Cortex M3 (readable)
             MemorySection(0x00326000, 0x0032ffff,  False, True),   # HW Regs Cortex M3 (readable)
             MemorySection(0x00338000, 0x00367fff,  False, True),   # HW Regs Cortex M3 (readable) + Pka Top
             MemorySection(0x00370000, 0x0037ffff,  False, True),   # RTX FIFO
             MemorySection(0x00390000, 0x00397fff,  False, True),   # Power WD
             #MemorySection(0x00404000, 0x00407fff,  False, True),   # EF Registers (seem to be sometimes unavailable)
             MemorySection(0x00410000, 0x00413fff,  False, True),   # BT Modem Registers
             MemorySection(0x00420000, 0x00423fff,  False, True),   # FM Modem Registers
             MemorySection(0x00430000, 0x00433fff,  False, True),   # MAC 15.4
             MemorySection(0x00440000, 0x00443fff,  False, True),   # SecEng Top
             MemorySection(0x00450000, 0x00453fff,  False, True),   # Capscan Top
             MemorySection(0x00500000, 0x006007ff,  False, True),   # EPM RAM (readable) + RF Regs
             MemorySection(0x00640000, 0x006407ff,  False, True),   # CLB Regs
             MemorySection(0x00650000, 0x006507ff,  False, True),   # GCI Regs
             MemorySection(0x20000000, 0x2024ffff,  False, True),   # SRAM
             MemorySection(0x20270000, 0x20283fff,  False, True),   # SRAM
             MemorySection(0x20500000, 0x200fffff,  False, True),   # SRAM
             MemorySection(0x22000000, 0x2226ffff,  False, True),   # SRAM Bits?

             MemorySection(0x40000000, 0x40003fff,  False, True),   # ToRam Alias / Peripherals
             MemorySection(0x42000000, 0x4207ffff,  False, True),   # ToRam Bits
             #MemorySection(0x60000000, 0x60000000,  False, True),   # Extern BlueRF SRAM (range TBD)
             #MemorySection(0xa0000000, 0xa0000000,  False, True),   # Extern Device Address (range TBD)
             MemorySection(0xe0000000, 0xe0100000,  False, True),   # Base PPB Address
            ]

# Patchram
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310404
PATCHRAM_VALUE_TABLE_ADDRESS    = 0x270000
PATCHRAM_NUMBER_OF_SLOTS        = 192
PATCHRAM_ALIGNED                = False
# only seems to work 4-byte aligned here ...


# Connection Struct and Table
CONNECTION_LIST_ADDRESS   = 0x216F98    # pRm_whole_conn = 0x280C9C points to this
CONNECTION_MAX            = 11          # g_bt_max_connections = 0 in firmware
CONNECTION_STRUCT_LENGTH  = 0x168       # ??

# Snippet for fuzzLmp()
FUZZLMP_HOOK_ADDRESS = 0xB08D8          # execute standard SendLmpPdu HCI to fill parameters
FUZZLMP_CODE_BASE_ADDRESS = 0x271A00    # memory area of other WICED patches
FUZZLMP_ASM_CODE = """
        // This hook is put into the end of bthci_cmd_vs_SendLmpPdu_B08AC,
        // so command parsing is still performed as normal. We jump in
        // before bthci_cmd_vs_SendLmpPdu pops and calls DHM_LMPTx.

        mov r0, r6 // 4 byte alignment

        // put length argument into table_entry
        // payload[5] holds the size argument
        ldr   r5, =table_entry
        add   r5, #4         // length offset within table entry
        ldrb r6, [r4, #5]    // size is in position r4+5
        strb r6, [r5]        

        // we need to do the original pop...
        pop  {r4-r6, lr}

        // now we simply continue like the original DHM_LMPTx_3453E function
        cmp   r1, #0
        itt   eq
        moveq r0, #4
        bxeq  lr
        push  {r4-r10, lr}   // code at 0x34546
        mov   r7, r0

        // part of the check if hook_LMP_TxFilter is installed
        ldr   r0, =0x203144 //dhmAvLinkAutoDetectEnable
        mov   r4, r1
        ldr   r2, [r0, #12]
        //cbz   r2, loc_34564

        ldr.w r8, [r7]         // code at 0x34564
        mov   r0, r8
        bl    0x93E60        // rm_getDHMAclPtr
        movs  r5, r0
        // skip check if we actually got a ptr 
        // continue at 0x3457A
        ldrb  r0, [r4, #12]
        tst.w r0, #0xfe     // test for extended op ...
        add.w r0, r3, #0xc
        

        // now we regularily would call the opcode conversion table function
        // however, we do not use lm_getLmpInfoType_86A82 but insert our own table here        
        ldr    r1, =table_entry // table_ptr with exactly one entry, so no offsets included here
        ldr    r0, =table_entry

        // branch back to DHM_LMPTx position after bl lm_getLmpInfoType
        b     0x3458A

        .align
        table_entry:
            .byte 0x40 //lm_LmpUnsupportedPdu
            .byte 0x6A 
            .byte 0x08
            .byte 0x00
            .byte 0x20  //length, will be overwritten by us anyways, but can not be longer than one buffer (0x20)  
            .byte 0x00    
            .byte 0x00
            .byte 0x00
        """


# Assembler snippet for tracepoints
# In contrast to the Nexus 5 patch, we uninstall ourselves automatically and use internal debug functions
TRACEPOINT_BODY_ASM_LOCATION = 0x00218500
TRACEPOINT_HOOKS_LOCATION = 0x00218700
TRACEPOINT_HOOK_SIZE = 40
TRACEPOINT_HOOK_ASM = """
        push {r0-r12, lr}       // save all registers on the stack (except sp and pc)
        ldr  r6, =0x%x          // addTracepoint() injects pc of original tracepoint here
        mov  r0, %d             // addTracepoint() injects the patchram slot of the hook patch
        bl   0x28794            // patch_uninstallPatchEntry(slot)
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
        bl   0x2DEF4     // hci_allocateEventBlockWithLen(0xff, 78)
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
        bl   0xEAB4   // memcpy(dst, src, len)

        // send HCI buffer to the host
        mov  r0, r4      // r4 still points to the beginning of the HCI buffer
        bl   0x2DEC0     // hci_sendEvent

        // restore status register
        msr  cpsr_f, r5
        
        bl 0x26C7A       // bthci_event_vs_DBFW_CoreDumpRAMImageEvent

        mov  lr, r8      // restore lr from r8
        bx   lr          // return
        


//0x00218561
        
"""
