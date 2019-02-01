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

# Memory Sections
#                          start,    end,      is_rom? is_ram?
SECTIONS = [ MemorySection(0x0,      0x90000,  True,  False),
             MemorySection(0xB08A0,  0xB08E8,  True,  False), #TODO
             MemorySection(0xd0000,  0xd8000,  False, True ),
            #MemorySection(0xe0000,  0x1f0000, True , False),
             MemorySection(0x200000, 0x228000, False, True ),
             MemorySection(0x260000, 0x268000, True , False),
            #MemorySection(0x280000, 0x2a0000, True , False),
             MemorySection(0x318000, 0x320000, False, False),
             MemorySection(0x324000, 0x360000, False, False),
             MemorySection(0x362000, 0x362100, False, False),
             MemorySection(0x363000, 0x363100, False, False),
             MemorySection(0x600000, 0x600800, False, False),
             MemorySection(0x640000, 0x640800, False, False),
             MemorySection(0x650000, 0x650800, False, False),
            #MemorySection(0x680000, 0x800000, False, False)
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