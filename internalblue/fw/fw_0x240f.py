#!/usr/bin/env python

# fw.py
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

from __future__ import absolute_import
from .fw import MemorySection, FirmwareDefinition


class BCM4358A3(FirmwareDefinition):
    # Firmware Infos
    # This runs on Nexus 6P, Samsung Galaxy S6, Samsung Galaxy S6 edge
    FW_NAME = "BCM4358A3"

    # Device Infos
    DEVICE_NAME = 0x213994  # [type: 1byte] [len: 1byte] [name: len byte] #works
    BD_ADDR = 0x201C48  # works

    # Memory Sections
    #                          start,    end,      is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x0, 0x9EF00, True, False),
        MemorySection(
            0xD0000, 0xD8000, False, True
        ),  # Patchram values with actual code / hooks
        # MemorySection(0xe0000,  0x1e0000, True , False), # all zero
        MemorySection(0x200000, 0x22A000, False, True),
        MemorySection(0x260000, 0x268000, True, False),
        # MemorySection(0x280000, 0x2a0000, True , False), # all zero
        MemorySection(0x300000, 0x301000, False, False),
        MemorySection(0x310000, 0x318000, False, True),  # Patchram addresses
        MemorySection(0x318000, 0x322000, False, False),
        MemorySection(0x324000, 0x368000, False, False),
        MemorySection(0x600000, 0x600800, False, False),
        MemorySection(0x640000, 0x640800, False, False),
        MemorySection(0x650000, 0x650800, False, False),
        # MemorySection(0x680000, 0x800000, False, False)
        # MemorySection(0x770000, 0x78ffff, False, False), #TODO maybe more, but all zero
    ]

    # Connection Struct and Table

    # Nexus 6P works differently:
    # address 0x21AD5C holds a list with pointers to connection structs!
    # CONNECTION_ARRAY_ADDRESS = 0x21ad88 #potentially the first valid address... but not part of an array
    # CONNECTION_ARRAY_SIZE    = 11 #is still 11 for Nexus 6P, but no longer hard-coded
    CONNECTION_LIST_ADDRESS = 0x21AD5C
    CONNECTION_MAX = 11
    CONNECTION_STRUCT_LENGTH = 0x168  # ??

    # Patchram
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000
    PATCHRAM_VALUE_TABLE_ADDRESS = 0xD0000
    PATCHRAM_NUMBER_OF_SLOTS = 192
    PATCHRAM_ALIGNED = False  # we can use standard ReadRAM HCI on Nexus 6P

    LAUNCH_RAM_PAUSE = 8  # bugfix: pause between multiple readMemAligned() calls in seconds
    # not a problem: doing multiple writeMem in a row
    # the thing that crashes: executing multiple launchRam() in a row: sendhcicmd 0xfc4e 0x473CC
    # crashes even when executing 0x5E860 twice, which is just a nullsub
    # also crashes during the pause if there are other hci events

    # Launch_RAM is faulty so we need to overwrite it. This is the position of the handler.
    LAUNCH_RAM = 0x260B84  # TODO this one needs to be handed with a "branch" (without link) instead of sub+1
    HCI_EVENT_COMPLETE = 0x229C

    # Snippet for sendLmpPacket()
    SENDLMP_CODE_BASE_ADDRESS = 0xD5130
    # TODO already works except for correct mac address - so still a problem with the connection #
    SENDLMP_ASM_CODE = """
            push {r4,lr}

            // malloc buffer for LMP packet
            bl 0x3AAA8      // malloc_0x20_bloc_buffer_memzero
            mov r4, r0      // store buffer for LMP packet inside r4

            // fill buffer
            add r0, 0xC         // The actual LMP packet must start at offset 0xC in the buffer.
                                // The first 12 bytes are (supposely?) unused and remain zero.
            ldr r1, =payload    // LMP packet is stored at the end of the snippet
            mov r2, 20          // Max. size of an LMP packet is 19 (I guess). The send_LMP_packet
                                // function will use the LMP opcode to lookup the actual size and
                                // use it for actually transmitting the correct number of bytes.
            bl  0x63900+1       // memcpy

            // load conn struct pointer (needed for determine if we are master or slave)
            mov r0, %d      // connection number is injected by sendLmpPacket()
            bl 0x473CC      // find connection struct from conn nr (r0 will hold pointer to conn struct)    //FIXME
            //FIXME: mac address is always 1f:8d:00:00:00:00

            // set tid bit if we are the slave
            ldr r1, [r0, 0x1c]  // Load a bitmap from the connection struct into r1.
            lsr r1, 15          // The 'we are master'-bit is at position 15 of this bitmap
            eor r1, 0x1         // invert and isolate the bit to get the correct value for the TID bit
            and r1, 0x1
            ldr r2, [r4, 0xC]   // Load the LMP opcode into r2. Note: The opcode was already shifted
                                // left by 1 bit (done by sendLmpPacket()). The TID bit goes into
                                // the LSB (least significant bit) of this shifted opcode byte.
            orr r2, r1          // insert the TID bit into the byte
            str r2, [r4, 0xC]   // Store the byte back into the LMP packet buffer


            // send LMP packet
            mov r1, r4      // load the address of the LMP packet buffer into r1.
                            // r0 still contains the connection number.
            pop {r4,lr}     // restore r4 and the lr
            b 0xAF4C        // branch to send_LMP_packet. send_LMP_packet will do the return for us.

            .align          // The payload (LMP packet) must be 4-byte aligend (memcpy needs aligned addresses)
            payload:        // Note: the payload will be appended here by the sendLmpPacket() function
            """

    # Assembler snippet for the readMemAligned() function
    READ_MEM_ALIGNED_ASM_LOCATION = 0xD5030
    READ_MEM_ALIGNED_ASM_SNIPPET = """
            push {r4, lr}

            // malloc HCI event buffer
            mov  r1, 0xff    // event code is 0xff (vendor specific HCI Event) 
            mov  r2, %d      // readMemAligned() injects the number of bytes it wants to read here 
            add  r2, 4       // + 'READ'
            mov  r0, r2
            adds r0, #2      // r0 needs to be 2 higher than r2 in all malloc_hci_event_buffer calls
            bl   0x22C4      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer)
            mov  r4, r0      // save pointer to the buffer in r4

            // append our custom header (the word 'READ') after the event code and event length field
            add  r0, 10      // write after the length field (offset 10 in event struct)
            ldr  r1, =0x44414552  // 'READ'
            str  r1, [r0]
            add  r0, 4      // advance the pointer. r0 now points to the beginning of our read data

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

            pop {r4, lr}    // return
            b   0x20F4      // send_hci_event()

        """
