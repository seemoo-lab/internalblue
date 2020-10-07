# from pwnlib.util.packing import *
import struct
from typing import Union


def bytes_to_hex(data):
    # type: (Union[bytes, bytearray]) -> str
    return "".join(format(x, "02x") for x in bytearray(data))


def p8(num):
    return struct.pack('B', num)


def p16(num):
    return struct.pack('H', num)


def p32(num):
    return struct.pack('I', num)


def u32(num):
    return struct.unpack('I', num)