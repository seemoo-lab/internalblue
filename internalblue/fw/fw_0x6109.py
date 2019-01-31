#!/usr/bin/env python2

# fw_0x6109.py
#
# All firmware specific data such as address offsets are collected
# in the fw.py file. Later versions of the framework will provide
# multiple copies of this file in order to target different firmware
# and chip versions.
#
# Copyright (c) 2018 Dennis Mantz. (MIT License)
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
# This runs on Nexus 5, Xperia Z3, Samsung Galaxy Note 3
FW_NAME = "BCM4335C0"

# Device Infos
DEVICE_NAME = 0x2178B4  # [type: 1byte] [len: 1byte] [name: len byte]
BD_ADDR = 0x210C2C


# Memory Sections
#                          start,    end,      is_rom? is_ram?
SECTIONS = [ MemorySection(0x0,      0x90000,  True , False),
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

# BLOC struct head which points to the first bloc struct (double-linked list)
BLOC_HEAD = 0x203094

# QUEU struct head which points to the first queue struct (double-linked list)
QUEUE_HEAD = 0x20307C
QUEUE_NAMES = ["hci_evt_send", "queue2", "queue3", "queue4", "queue5", "hci_recv",
               "queue7", "queue8", "queue9", "queue10", "queue11", "queue12",
               "hci_uart_type7", "queue14", "hci_sco", "queue16"]   # TODO: better names


# Connection Structure and Table
CONNECTION_ARRAY_ADDRESS = 0x002038E8
CONNECTION_MAX           = 11
CONNECTION_STRUCT_LENGTH = 0x14C


# Patchram
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000
PATCHRAM_VALUE_TABLE_ADDRESS    = 0xd0000
PATCHRAM_NUMBER_OF_SLOTS        = 128
PATCHRAM_ALIGNED                = True #use readMemAligned, not accessible via ReadRAM HCI command on Nexus 5


# Snippet for sendLmpPacket()
SENDLMP_CODE_BASE_ADDRESS = 0xd7500
SENDLMP_ASM_CODE = """
        push {r4,lr}

        // malloc buffer for LMP packet
        bl 0x3F17E      // malloc_0x20_bloc_buffer_memzero
        mov r4, r0      // store buffer for LMP packet inside r4

        // fill buffer
        add r0, 0xC         // The actual LMP packet must start at offset 0xC in the buffer.
                            // The first 12 bytes are (supposely?) unused and remain zero.
        ldr r1, =payload    // LMP packet is stored at the end of the snippet
        mov r2, 20          // Max. size of an LMP packet is 19 (I guess). The send_LMP_packet
                            // function will use the LMP opcode to lookup the actual size and
                            // use it for actually transmitting the correct number of bytes.
        bl  0x2e03c         // memcpy

        // load conn struct pointer (needed for determine if we are master or slave)
        mov r0, %d      // connection number is injected by sendLmpPacket()
        bl 0x42c04      // find connection struct from conn nr (r0 will hold pointer to conn struct)

        // set tid bit if we are the slave
        ldr r1, [r0, 0x1c]  // Load a bitmap from the connection struct into r1.
        lsr r1, 15          // The 'we are master'-bit is at position 15 of this bitmap
        and r1, 0x1         // isolate the bit to get the correct value for the TID bit
        ldr r2, [r4, 0xC]   // Load the LMP opcode into r2. Note: The opcode was already shifted
                            // left by 1 bit (done by sendLmpPacket()). The TID bit goes into
                            // the LSB (least significant bit) of this shifted opcode byte.
        orr r2, r1          // insert the TID bit into the byte
        str r2, [r4, 0xC]   // Store the byte back into the LMP packet buffer


        // send LMP packet
        mov r1, r4      // load the address of the LMP packet buffer into r1.
                        // r0 still contains the connection number.
        pop {r4,lr}     // restore r4 and the lr
        b 0xf81a        // branch to send_LMP_packet. send_LMP_packet will do the return for us.

        .align          // The payload (LMP packet) must be 4-byte aligend (memcpy needs aligned addresses)
        payload:        // Note: the payload will be appended here by the sendLmpPacket() function
        """

# Assembler snippet for the readMemAligned() function
READ_MEM_ALIGNED_ASM_LOCATION = 0xd7900
READ_MEM_ALIGNED_ASM_SNIPPET = """
        push {r4, lr}

        // malloc HCI event buffer
        mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
        mov  r1, %d      // readMemAligned() injects the number of bytes it wants to read here
        add  r1, 6       // + type and length + 'READ'
        bl   0x7AFC      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer)
        mov  r4, r0      // save pointer to the buffer in r4

        // append our custom header (the word 'READ') after the event code and event length field
        add  r0, 2            // write after the length field
        ldr  r1, =0x44414552  // 'READ'
        str  r1, [r0]
        add  r0, 4            // advance the pointer. r0 now points to the beginning of our read data

        // copy data to buffer
        ldr  r1, =0x%x  // readMemAligned() injects the read_address here. r1 will be used as src pointer in the loop
        mov  r2, %d     // readMemAligned() injects the number of dwords to read here. r2 will be the loop counter
    loop:
        ldr  r3, [r1]   // read 4 bytes from the read_address
        str  r3, [r0]   // store them inside the HCI buffer
        add  r0, 4      // advance the buffer pointer
        add  r1, 4      // advance the read_address
        subs r2, 1      // decrement the loop variable
        bne  loop       // branch if r2 is not zero yet

        // send HCI buffer to the host
        mov r0, r4      // r4 still points to the beginning of the HCI buffer
        bl  0x398c1     // send_hci_event_without_free()

        // free HCI buffer
        mov r0, r4
        bl  0x3FA36     // free_bloc_buffer_aligned

        pop {r4, pc}    // return
    """

# Assembler snippet for tracepoints
TRACEPOINT_BODY_ASM_LOCATION = 0xd7a00
TRACEPOINT_HOOKS_LOCATION = 0xd7b00
TRACEPOINT_HOOK_SIZE = 28
TRACEPOINT_HOOK_ASM = """
        push {r0-r12, lr}       // save all registers on the stack (except sp and pc)
        ldr  r6, =0x%x          // addTracepoint() injects pc of original tracepoint here
        mov  r7, %d             // addTracepoint() injects the patchram slot of the hook patch
        bl   0x%x               // addTracepoint() injects TRACEPOINT_BODY_ASM_LOCATION here
        pop  {r0-r12, lr}       // restore registers

        // branch back to the original instruction
        b 0x%x                  // addTracepoint() injects the address of the tracepoint
"""
TRACEPOINT_RAM_DUMP_PKT_COUNT = 670     # <ramsize> / <packetsize>   where packetsize is 244
TRACEPOINT_BODY_ASM_SNIPPET = """
        mov   r8, lr     // save link register in r8

        // save status register in r5
        mrs  r5, cpsr

        // malloc HCI event buffer
        mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
        mov  r1, 76      // buffer size: size of registers (68 bytes) + type and length + 'TRACE_'
        bl   0x7AFC      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer)
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
        bl   0x2e03c+1   // memcpy(dst, src, len)

        // send HCI buffer to the host
        mov  r0, r4      // r4 still points to the beginning of the HCI buffer
        bl   0x398c1     // send_hci_event_without_free()

        // free HCI buffer
        mov  r0, r4
        bl   0x3FA36     // free_bloc_buffer_aligned

        mov  r0, r7      // r7 still contains the patchram slot number
        bl   0x311AA     // disable_patchram_slot(slot)

        // restore status register
        msr  cpsr_f, r5

        // dump ram
        bl   dump_ram

        mov  lr, r8      // restore lr from r8
        bx   lr          // return


// function to dump the RAM as multiple HCI packets:
dump_ram:
        push {r4-r6,lr}

        // malloc HCI event buffer
        mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
        mov  r1, 252     // buffer size
        bl   0x7AFC      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer)
        mov  r4, r0      // save pointer to the buffer in r4

        // append our custom header (the word 'RAM___') after the event code and event length field
        add  r0, 2            // write after the length field
        ldr  r1, =0x5f4d4152  // 'RAM_'
        str  r1, [r0]
        add  r0, 4            // advance the pointer.
        ldr  r1, =0x5f5f      // '__'
        strh r1, [r0]
        add  r0, 2            // advance the pointer. r0 now points to the start of the actual payload

        mov  r5, 0x200000     // start of ram
        ldr  r6, =%d          // number of ramdump packets to be sent

        dump_ram_loop:
            // Set r0 to point to the beginning of the payload in the hci buffer
            mov  r0, r4
            add  r0, 8

            // store current address
            str  r5, [r0]    // r5 contains the address in RAM which is send next
            add  r0, 4       // advance the pointer.

            // copy ram to hci buffer
            mov  r1, r5
            mov  r2, 244
            bl   0x2e03c     // memcpy

            // send HCI buffer to the host
            mov  r0, r4      // r4 still points to the beginning of the HCI buffer
            bl   0x398c1     // send_hci_event_without_free()

            // delay loop; Workaround: without the delay, a lot of packets are not actually sent
            // through HCI.
            mov  r0, 0x1000
            delay_loop:
                subs r0, 1
                bne delay_loop

            // increment the RAM pointer; decrement the counter
            add  r5, 244
            subs r6, 1

            bne  dump_ram_loop

        // free HCI buffer
        mov  r0, r4
        bl   0x3FA36     // free_bloc_buffer_aligned

        pop  {r4-r6,pc}
""" % TRACEPOINT_RAM_DUMP_PKT_COUNT
