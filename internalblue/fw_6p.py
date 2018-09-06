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
DEVICE_NAME = 0x213994  # [type: 1byte] [len: 1byte] [name: len byte] #works
BD_ADDR = 0x201C48 #works


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
SECTIONS = [ MemorySection(0x0,      0x9ef00,  True , False),
             MemorySection(0xd0000,  0xd8000,  False, True ), # Patchram values with actual code / hooks
            #MemorySection(0xe0000,  0x1e0000, True , False), # all zero
             MemorySection(0x200000, 0x22a000, False, True ),
             MemorySection(0x260000, 0x268000, True , False),
            #MemorySection(0x280000, 0x2a0000, True , False), # all zero
             MemorySection(0x300000, 0x301000, False, False),
             MemorySection(0x310000, 0x318000, False, True ), # Patchram addresses
             MemorySection(0x318000, 0x322000, False, False),
             MemorySection(0x324000, 0x368000, False, False),
             MemorySection(0x600000, 0x600800, False, False),
             MemorySection(0x640000, 0x640800, False, False),
             MemorySection(0x650000, 0x650800, False, False),
            #MemorySection(0x680000, 0x800000, False, False)
             #MemorySection(0x770000, 0x78ffff, False, False), #TODO maybe more, but all zero
            ]


# Connection Struct and Table
#CONNECTION_ARRAY_ADDRESS = 0x201c20 #0x00208E55 # TODO ?? ... might also be around 00208E60, 0x201c2c seems to be wrong
#CONNECTION_ARRAY_ADDRESS  = 0x218EA8; # correct according to get_ptr_to_connection_struct_from_index
#CONNECTION_ARRAY_ADDRESS = 0x218ed4; #seems to work for Eifon
CONNECTION_ARRAY_ADDRESS = 0x201C2C
#CONNECTION_ARRAY_ADDRESS  = 0x21AD5C # from find_connection_struct_by_number
CONNECTION_ARRAY_SIZE    = 11 #is still 11 for Nexus 6P, but no longer hard-coded
CONNECTION_STRUCT_LENGTH = 0x14C
# hexdump 0x201c20 --length 0x14c
# hexdump 0x201c48 --length 0x6 -> own BT_ADDR from first connection struct




# Patchram
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204 #done, seems to be be similar
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000 #done, seems to be similar
PATCHRAM_VALUE_TABLE_ADDRESS    = 0xd0000 #done, seems to be similar
PATCHRAM_NUMBER_OF_SLOTS        = 192 #was 128, many 0x80 are now 0xc0   


LAUNCH_RAM_PAUSE = 8 # bugfix: pause between multiple readMemAligned() calls in seconds
# not a problem: doing multiple writeMem in a row
# the thing that crashes: executing multiple launchRam() in a row: sendhcicmd 0xfc4e 0x473CC
# crashes even when executing 0x5E860 twice, which is just a nullsub
# also crashes during the pause if there are other hci events


# LMP

# These arrays contain the sizes for LMP packets (including the opcode) depending
# on the LMP opcode or escaped LMP opcode. The values can be obtained from the BT
# specification or from the LMP handler table in the firmware.
LMP_LENGTHS = [0, 2, 17, 2, 3, 1, 3, 2, 17, 17, 17, 17, 5, 17, 17, 2, 2, 17, 1, 5, 7, 7, 0, 10, 1, 17, 0, 6, 13, 9, 15, 2, 2, 1, 1, 1, 2, 6, 6, 9, 9, 4, 4, 7, 3, 2, 2, 1, 3, 1, 1, 1, 9, 3, 3, 3, 1, 10, 1, 3, 16, 4, 17, 17, 17, 17, 17, 0, 0, 0]
LMP_ESC_LENGTHS = [0, 4, 5, 12, 12, 15, 3, 6, 0, 0, 0, 3, 16, 4, 0, 0, 7, 12, 0, 0, 0, 9, 9, 2, 2, 5, 5, 2, 2, 2, 3, 3, 3, 2, 2]

# Hooks for the LMP Monitor Mode
LMP_SEND_PACKET_HOOK            = 0x2023FC  # This address contains the hook function for LMP_send_packet
                                            # It is NULL by default. If we set it to a function address,
                                            # the function will be called by LMP_send_packet.
LMP_MONITOR_HOOK_BASE_ADDRESS   = 0xd5230   # Start address for the INJECTED_CODE 
LMP_MONITOR_LMP_HANDLER_ADDRESS = 0x3AD46   # LMP_Dispatcher_3F3F4

#FIXME still has a problem inserting the mac address in recv direction
LMP_MONITOR_INJECTED_CODE = """
    // Jump Table
    // bl BUFFER_BASE_ADDRESS+1 executes hook_send_lmp
    // bl BUFFER_BASE_ADDRESS+1+4 executes hook_recv_lmp
    b hook_send_lmp
    b hook_recv_lmp
    
    hook_recv_lmp:    
    
        // we overwrite the first 4 bytes of LMP_Dispatcher with 'b hook_recv_lmp' via patchram
        push {r2-r8, lr}  // restore the first 4 bytes of LMP_Dispatcher which pushes the registers        
        push {r0-r5, lr} // we use r0-r5 locally
        
        mov r5, r0       // backup of empty connection struct ptr
        
        // malloc HCI event buffer
        mov  r1, 0xff    // HCI header: len=0x2c   event code=0xff
        mov  r2, 0x2c    // 
        add  r2, 4       // + '_LMP'
        mov  r0, r2
        adds r0, #2      // r0 needs to be 2 higher than r2 in all malloc_hci_event_buffer calls
        bl   0x22C4      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer), don't use custom buffer here
        mov  r4, r0      // save pointer to the buffer in r4
        
        // append our custom header (the word '_LMP') after the event code and event length field
        add  r0, 10      // write after the length field (offset 10 in event struct)
        ldr  r1, =0x504d4c5f  // '_LMP'
        str  r1, [r0]
        add  r0, 4          // advance the pointer. r0 now points to the beginning of our own lmp data
        ldr  r1, =0x015f    // continuation of custom header: '_\x01'; 01 for 'lmp recv'
        strh r1, [r0]       // Full header: _LMP_<type>    where type is 0x00 for lmp send
        add  r0, 2          //                                           0x01 for lmp recv
        
        // read remote bt addr from connection struct
        //TODO definitely broken, inserts wrong address
        //TODO but "info connections" also does not work yet, so probably that's the problem?         
        push {r0-r2, lr}
        mov  r0, r5 //restore empty connection struct ptr 
        add  r0, 2 //connection index offset
        ldrh r0, [r0]
        bl   0x473CC+1 //get_ptr_to_connection_struct_from_index
        mov  r5, r0
        pop  {r0-r2, lr}
        ldr  r1, [r5]
        add  r1, 0x28       // at offset 0x28 is the remote BT address located
        mov  r2, 6          // memcpy the BT address into the temp. buffer
        bl   0x63900+1      // memcpy 
        
        

        //// read LMP payload data and store it inside the temp. buffer
        ldr  r1, =0x202198  // r1 = rx_info_data_200478
        ldr  r2, [r1]       // first 4 byte of rx_info_data contains connection number
        str  r2, [r0]       // copy the complete 4 bytes to the temp. buffer (we have space :))
        add  r0, 4
        add  r1, 4          // r1 = rx_info_data_200478 + 4 which contains the ptr to the data
        ldr  r1, [r1]       // r1 = ptr to the data.
        add  r1, 0xC        // The actual LMP payload starts at offset 0xC
        mov  r2, 24         // size for memcpy (max size of LMP should be 19 bytes; just to be safe do 24)
        bl   0x63900+1      // memcpy

        // send HCI buffer to the host
        mov r0, r4       // r4 still points to the beginning of the HCI buffer

        bl   0x20F4      // send_hci_event()
        
        pop {r0-r5, lr}  // reset local registers
        b    0x3AD4A     // return to LMP_Dispatcher + 4 (after our 'b hook_recv_lmp' )
        
        
    hook_send_lmp: //works like 4 times and then creates infinite loop
        push {r4,r5,r6,lr}  // save some registers we want to use
        

        // save function parameters of the LMP_send_packet function
        mov  r5, r0         // pointer to connection struct for the packet
        mov  r4, r1         // buffer (LMP payload)
        
        // malloc HCI event buffer
        mov  r1, 0xff    // HCI header: len=0x2c   event code=0xff
        mov  r2, 0x2c    // len
        add  r2, 4       // len + len('_LMP')
        mov  r0, r2
        adds r0, #2      // r0 needs to be 2 higher than r2 in all malloc_hci_event_buffer calls
        bl   0x22C4      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer) 
        mov  r6, r0      // save pointer to the buffer in r6

        // append our custom header (the word '_LMP') after the event code and event length field
        add  r0, 10      // write after the length field (offset 10 in event struct)
        ldr  r1, =0x504d4c5f  // '_LMP'
        str  r1, [r0]
        add  r0, 4      // advance the pointer. r0 now points to the beginning of our read data
        ldr  r1, =0x005f    // continuation of custom header: '_\x01'; 01 for 'lmp recv'
        strh r1, [r0]       // Full header: _LMP_<type>    where type is 0x00 for lmp send
        add  r0, 2          //                                           0x01 for lmp recv
        
        // get bt addr of remote device from connection struct
        mov  r1, r5         // r5 is ptr to connection struct
        add  r1, 0x28       // BT address is at offset 0x28
        mov  r2, 6
        bl   0x63900+1      // memcpy
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
        bl   0x63900+1      // memcpy 


        // send HCI buffer to the host
        mov r0, r6      // r6 still points to the beginning of the HCI buffer


        bl   0x20F4      // send_hci_event()
        
        mov r0, 0           // we need to return 0 to indicate to the hook code
                            // that the original LMP_send_packet function should
                            // continue to be executed
        
        pop  {r4,r5,r6,pc}  // restore saved registers and return
    """




# Snippet for sendLmpPacket()
SENDLMP_CODE_BASE_ADDRESS = 0xd5130
#TODO already works except for correct mac address - so still a problem with the connection #
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
READ_MEM_ALIGNED_ASM_LOCATION = 0xd5030 
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


