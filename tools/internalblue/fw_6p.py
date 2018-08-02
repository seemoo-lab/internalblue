#!/usr/bin/python2

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

DEVICE_NAME = 0x213994  # [type: 1byte] [len: 1byte] [name: len byte] #works
BD_ADDR = 0x201C48 #works

#CONNECTION_ARRAY_ADDRESS = 0x002038E8
CONNECTION_ARRAY_ADDRESS =  0x00208E55 # TODO ?? ... looks different ... might also be around 00208E60, 0x201c2c seems to be wrong
CONNECTION_ARRAY_SIZE    = 11
CONNECTION_STRUCT_LENGTH = 0x14C

#LMP options

LMP_SEND_PACKET_HOOK = 0x2023FC #done
LMP_LENGTHS = [0, 2, 17, 2, 3, 1, 3, 2, 17, 17, 17, 17, 5, 17, 17, 2, 2, 17, 1, 5, 7, 7, 0, 10, 1, 17, 0, 6, 13, 9, 15, 2, 2, 1, 1, 1, 2, 6, 6, 9, 9, 4, 4, 7, 3, 2, 2, 1, 3, 1, 1, 1, 9, 3, 3, 3, 1, 10, 1, 3, 16, 4, 17, 17, 17, 17, 17, 0]
LMP_ESC_LENGTHS = [0, 4, 5, 12, 12, 12, 8, 3, 0, 0, 0, 3, 16, 4, 0, 0, 7, 12, 0, 0, 0, 9, 9, 2, 2, 5, 5, 2, 2, 2, 3, 3, 3]

HOOK_BASE_ADDRESS = 0x117020 #0xd7600 #TODO might not always be empty
BUFFER_BASE_ADDRESS = 0x117120 #0xd7700
BUFFER_LEN = 0x80
LMP_HANDLER = 0x3AD46  #done 
INJECTED_CODE = """
    b hook_send_lmp
    b hook_recv_lmp

    hook_recv_lmp:
        push {r2-r8,lr}
        push {r0-r4,lr}

        // write hci event header
        ldr  r0, =0x%x
        mov  r4, r0
        mov  r3, r0
        ldr  r1, =0x2cff      // len: 0x2c   event code: 0xff
        strh r1, [r0]
        add  r0, 2
        ldr  r1, =0x504d4c5f  // '_LMP'
        str  r1, [r0]
        add  r0, 4
        ldr  r1, =0x015f  // '_\x01' 01 for 'lmp recv'
        strh r1, [r0]
        add  r0, 2

        // read remote bt addr
        ldr  r1, =0x20219A  // done, maybe_rx_info_data+3
        ldrb r2, [r1]       // connection number
        sub  r2, 1
        mov  r1, 0x14C
        mul  r2, r1
        ldr  r1, =0x2038E8  // connection array
        add  r1, r2
        add  r1, 0x28
        mov  r2, 6
        bl   0x63900+1  // done, memcpy
        // memcpy returns end of dst buffer (8 byte aligned)

        // read data
        ldr  r1, =0x202198 // done, maybe_rx_info_data
        ldr  r2, [r1]
        str  r2, [r0]
        add  r0, 4
        add  r1, 4
        ldr  r1, [r1]
        add  r1, 0xC    // start of LMP packet
        mov  r2, 24     // size for memcpy
        bl   0x63900+1  // done, memcpy

        // send via hci
        mov  r0, r4
        bl   0x650 // TODO - probably not ... send_hci_event_without_free()

        pop  {r0-r4,lr}
        b    0x3F3F8

    hook_send_lmp:
        push {r4,r5,r6,lr}

        // save parameters
        mov  r5, r0 // conn struct
        mov  r4, r1 // buffer

        // write hci event header
        ldr  r0, =0x%x
        mov  r6, r0
        ldr  r1, =0x2cff      // len: 0x2c   event code: 0xff
        strh r1, [r0]
        add  r0, 2
        ldr  r1, =0x504d4c5f  // '_LMP'
        str  r1, [r0]
        add  r0, 4
        ldr  r1, =0x005f  // '_\x00' 00 for 'lmp recv'
        strh r1, [r0]
        add  r0, 2

        // get bt addr
        mov  r1, r5
        add  r1, 0x28
        mov  r2, 6
        bl   0x63900+1  // done, memcpy
        // memcpy returns end of dst buffer (8 byte aligned)

        // get connection number
        mov  r1, 0
        str  r1, [r0]
        add  r0, 2
        ldr  r2, [r5]
        strb r2, [r0]
        add  r0, 2

        // read data
        add  r1, r4, 0xC    // start of LMP packet

        mov  r2, 24
        bl   0x63900+1  // done, memcpy

        // send via hci
        mov  r0, r6
        bl   0x650 // TODO - probably not ... send_hci_event_without_free()

        mov r0, 0
        pop  {r4,r5,r6,pc}
    """ % (BUFFER_BASE_ADDRESS, BUFFER_BASE_ADDRESS+0x40)
