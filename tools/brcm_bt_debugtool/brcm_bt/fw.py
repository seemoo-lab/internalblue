#!/usr/bin/python2

# Dennis Mantz

DEVICE_NAME = 0x2178B4  # [type: 1byte] [len: 1byte] [name: len byte]
BD_ADDR = 0x210C2C

LMP_SEND_PACKET_HOOK = 0x200d38
LMP_LENGTHS = [0, 2, 17, 2, 3, 1, 3, 2, 17, 17, 17, 17, 5, 17, 17, 2, 2, 17, 1, 5, 7, 7, 0, 10, 1, 17, 0, 6, 13, 9, 15, 2, 2, 1, 1, 1, 2, 6, 6, 9, 9, 4, 4, 7, 3, 2, 2, 1, 3, 1, 1, 1, 9, 3, 3, 3, 1, 10, 1, 3, 16, 4, 17, 17, 17, 17, 17, 0]
LMP_ESC_LENGTHS = [0, 4, 5, 12, 12, 12, 8, 3, 0, 0, 0, 3, 16, 4, 0, 0, 7, 12, 0, 0, 0, 9, 9, 2, 2, 5, 5, 2, 2, 2, 3, 3, 3]

CONNECTION_ARRAY_ADDRESS = 0x002038E8
CONNECTION_ARRAY_SIZE    = 11
CONNECTION_STRUCT_LENGTH = 0x14C
