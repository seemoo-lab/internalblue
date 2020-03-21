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


class BCM4345B0(FirmwareDefinition):
    # Firmware Infos
    # iPhone 6
    FW_NAME = "BCM4345B0"


    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x000C07FF, True, False),  # Internal ROM
        MemorySection(
            0x000D0000, 0x000DFFFF, False, True
        ),  # Internal Memory Patchram Contents
        MemorySection(0x00200400, 0x00201CFF, False, True),  # Internal Memory Cortex M3
    ]

    # Patchram
    PATCHRAM_TARGET_TABLE_ADDRESS = 0x310000  # needs to be aligned read
    PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
    PATCHRAM_VALUE_TABLE_ADDRESS = 0xD0000
    PATCHRAM_NUMBER_OF_SLOTS = 128
    PATCHRAM_ALIGNED = True


    # Assembler snippet for the readMemAligned() function
    READ_MEM_ALIGNED_ASM_LOCATION = 0x215000  # there is nothing free until 0xdffff, but 0x215000 looks okay during runtime
    READ_MEM_ALIGNED_ASM_SNIPPET = """
            push {r4, lr}
    
            // malloc HCI event buffer
            mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
            mov  r1, %d      // readMemAligned() injects the number of bytes it wants to read here
            add  r1, 6       // + type and length + 'READ'
            bl   0x15DD4      // hci_sendEvent (will automatically copy event code and length into the buffer)
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
            bl  0x573B8     // send_hci_event_without_free()
    
            // free HCI buffer
            mov r0, r4
            bl  0x581AE     // osapi_blockPoolFree
    
            pop {r4, pc}    // return
         """
