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

DEVICE_NAME = 0x2178B4  # [type: 1byte] [len: 1byte] [name: len byte]
BD_ADDR = 0x210C2C

LMP_SEND_PACKET_HOOK = 0x200d38
LMP_LENGTHS = [0, 2, 17, 2, 3, 1, 3, 2, 17, 17, 17, 17, 5, 17, 17, 2, 2, 17, 1, 5, 7, 7, 0, 10, 1, 17, 0, 6, 13, 9, 15, 2, 2, 1, 1, 1, 2, 6, 6, 9, 9, 4, 4, 7, 3, 2, 2, 1, 3, 1, 1, 1, 9, 3, 3, 3, 1, 10, 1, 3, 16, 4, 17, 17, 17, 17, 17, 0]
LMP_ESC_LENGTHS = [0, 4, 5, 12, 12, 12, 8, 3, 0, 0, 0, 3, 16, 4, 0, 0, 7, 12, 0, 0, 0, 9, 9, 2, 2, 5, 5, 2, 2, 2, 3, 3, 3]

CONNECTION_ARRAY_ADDRESS = 0x002038E8
CONNECTION_ARRAY_SIZE    = 11
CONNECTION_STRUCT_LENGTH = 0x14C
