#!/usr/bin/env python2

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

# Device Infos
DEVICE_NAME = 0x2178B4  # [type: 1byte] [len: 1byte] [name: len byte]
BD_ADDR = 0x210C2C


# Memory Sections
class MemorySection:
    def __init__(self, start_addr, end_addr, is_rom, is_ram):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.is_rom = is_rom
        self.is_ram = is_ram

    def size(self):
        return self.end_addr - self.start_addr

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


# Connection Structure and Table
CONNECTION_ARRAY_ADDRESS = 0x002038E8
CONNECTION_ARRAY_SIZE    = 11
CONNECTION_STRUCT_LENGTH = 0x14C


# Patchram
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000
PATCHRAM_VALUE_TABLE_ADDRESS    = 0xd0000
PATCHRAM_NUMBER_OF_SLOTS        = 128


# LMP

# These arrays contain the sizes for LMP packets (including the opcode) depending
# on the LMP opcode or escaped LMP opcode. The values can be obtained from the BT
# specification or from the LMP handler table in the firmware.
LMP_LENGTHS = [0, 2, 17, 2, 3, 1, 3, 2, 17, 17, 17, 17, 5, 17, 17, 2, 2, 17, 1, 5, 7, 7, 0, 10, 1, 17, 0, 6, 13, 9, 15, 2, 2, 1, 1, 1, 2, 6, 6, 9, 9, 4, 4, 7, 3, 2, 2, 1, 3, 1, 1, 1, 9, 3, 3, 3, 1, 10, 1, 3, 16, 4, 17, 17, 17, 17, 17, 0]
LMP_ESC_LENGTHS = [0, 4, 5, 12, 12, 12, 8, 3, 0, 0, 0, 3, 16, 4, 0, 0, 7, 12, 0, 0, 0, 9, 9, 2, 2, 5, 5, 2, 2, 2, 3, 3, 3]

# Hooks for the LMP Monitor Mode
LMP_SEND_PACKET_HOOK            = 0x200d38  # This address contains the hook function for LMP_send_packet
                                            # It is NULL by default. If we set it to a function address,
                                            # the function will be called by LMP_send_packet.
LMP_MONITOR_HOOK_BASE_ADDRESS   = 0xd7600   # Start address for the INJECTED_CODE
LMP_MONITOR_BUFFER_BASE_ADDRESS = 0xd7700   # Address of the temporary buffer for the HCI event
LMP_MONITOR_BUFFER_LEN          = 0x80      # Length of the temporary BUFFER
LMP_MONITOR_LMP_HANDLER_ADDRESS = 0x3f3f4   # LMP_Dispatcher_3F3F4 (aka 'LMP_Dispatcher')
LMP_MONITOR_INJECTED_CODE = """
    // Jump Table
    // bl BUFFER_BASE_ADDRESS+1 executes hook_send_lmp
    // bl BUFFER_BASE_ADDRESS+1+4 executes hook_recv_lmp
    b hook_send_lmp
    b hook_recv_lmp

    // Hook for the LMP receive path (intercepts incomming LMP packets
    // and sends them to the host via HCI)
    // hook_recv_lmp uses BUFFER_BASE_ADDRESS as temp. buffer for the HCI event
    hook_recv_lmp:
        push {r2-r8,lr}     // this is the original push from the hooked function LMP_Dispatcher
                            // (we have to do it here as we overwrote if with the hook patch)
        push {r0-r4,lr}     // this is to save the registers so we can overwrite
                            // them in this function

        // write hci event header to beginning of the temp. buffer
        ldr  r0, =0x%x      // adr of buffer in r0
                            // (r0 will be increased as we write to the buffer)
        mov  r4, r0         // and also backup the address in r4
        mov  r3, r0         // TODO: this is unused. remove?
        ldr  r1, =0x2cff    // HCI header: len=0x2c   event code=0xff
        strh r1, [r0]       // write HCI header to buffer
        add  r0, 2          // advance pointer
        ldr  r1, =0x504d4c5f  // Beginning of my custom header: '_LMP'
        str  r1, [r0]
        add  r0, 4
        ldr  r1, =0x015f    // continuation of custom header: '_\x01'; 01 for 'lmp recv'
        strh r1, [r0]       // Full header: _LMP_<type>    where type is 0x00 for lmp send
        add  r0, 2          //                                           0x01 for lmp recv

        // read remote bt addr from connection struct
        ldr  r1, =0x20047a  // adr inside rx_info_data_200478 at which the conn. number is stored
        ldrb r2, [r1]       // store connection number in r2
        sub  r2, 1          // connection nr minus 1 results in the connection array index
        mov  r1, 0x14C      // size r1 = size of connection struct
        mul  r2, r1         // calculate offset of connection struct entry inside the array
        ldr  r1, =0x2038E8  // address of connection array start
        add  r1, r2         // store address of connection struct in r1
        add  r1, 0x28       // at offset 0x28 is the remote BT address located
        mov  r2, 6          // memcpy the BT address into the temp. buffer
        bl   0x2e03c+1      // memcpy
        // memcpy returns end of dst buffer (8 byte aligned)
        // that means r0 now points after the BT address inside the temp. buffer

        // read LMP payload data and store it inside the temp. buffer
        ldr  r1, =0x200478  // r1 = rx_info_data_200478 
        ldr  r2, [r1]       // first 4 byte of rx_info_data contains connection number
        str  r2, [r0]       // copy the complete 4 bytes to the temp. buffer (we have space :))
        add  r0, 4
        add  r1, 4          // r1 = rx_info_data_200478 + 4 which contains the ptr to the data
        ldr  r1, [r1]       // r1 = ptr to the data.
        add  r1, 0xC        // The actual LMP payload starts at offset 0xC
        mov  r2, 24         // size for memcpy (max size of LMP should be 19 bytes; just to be safe do 24)
        bl   0x2e03c+1      // memcpy

        // send HCI event packet (aka our temp. buffer)
        mov  r0, r4         // r4 still contains the start address of the temp. buffer
        bl   0x398c1        // send_hci_event_without_free()

        pop  {r0-r4,lr}     // restore the registers we saved
        b    0x3F3F8        // branch back into LMP_Dispatcher


    // Hook for the LMP send path (intercepts outgoing LMP packets
    // and sends them to the host via HCI)
    // hook_recv_lmp uses BUFFER_BASE_ADDRESS+40 as temp. buffer for the HCI event
    hook_send_lmp:
        push {r4,r5,r6,lr}  // save some registers we want to use

        // save function parameters of the LMP_send_packet function
        mov  r5, r0         // pointer to connection struct for the packet
        mov  r4, r1         // buffer (LMP payload)

        // write hci event header to temp. buffer
        ldr  r0, =0x%x      // this is BUFFER_BASE_ADDRESS+40 (out temp. buffer)
        mov  r6, r0         // save start address of temp. buffer in r6
        ldr  r1, =0x2cff    // HCI header: len=0x2c   event code=0xff
        strh r1, [r0]       // write HCI header to temp. buffer
        add  r0, 2
        ldr  r1, =0x504d4c5f // Beginning of my custom header: '_LMP'
        str  r1, [r0]
        add  r0, 4
        ldr  r1, =0x005f    // continuation of custom header: '_\x00'; 01 for 'lmp send'
        strh r1, [r0]       // Full header: _LMP_<type>    where type is 0x00 for lmp send
        add  r0, 2          //                                           0x01 for lmp recv

        // get bt addr of remote device from connection struct
        mov  r1, r5         // r5 is ptr to connection struct
        add  r1, 0x28       // BT address is at offset 0x28
        mov  r2, 6
        bl   0x2e03c+1      // memcpy
        // memcpy returns end of dst buffer (8 byte aligned)
        // that means r0 now points after the BT address inside the temp. buffer

        // get connection number (we send it to the host to be consistent with the
        // receive path; actually it is not used)
        mov  r1, 0          // first write 4 zero-bytes
        str  r1, [r0]
        add  r0, 2          // then write the conn. number in the middle of the bytes
        ldr  r2, [r5]       // conn. number is at offset 0x0 of the conn. struct
        strb r2, [r0]
        add  r0, 2

        // read LMP data and store the LMP payload into the temp. buffer
        add  r1, r4, 0xC    // start of LMP packet is at offset 0xC of rx_info_data_200478
        mov  r2, 24         // size for memcpy (max size of LMP should be 19 bytes; just to be safe do 24)
        bl   0x2e03c+1      // memcpy

        // send HCI event packet (aka our temp. buffer)
        mov  r0, r6         // r6 contains start address of the temp. buffer
        bl   0x398c1        // send_hci_event_without_free()

        mov r0, 0           // we need to return 0 to indicate to the hook code
                            // that the original LMP_send_packet function should
                            // continue to be executed
        pop  {r4,r5,r6,pc}  // restore saved registers and return
    """ % (LMP_MONITOR_BUFFER_BASE_ADDRESS, LMP_MONITOR_BUFFER_BASE_ADDRESS+0x40)


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
