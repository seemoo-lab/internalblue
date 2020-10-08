import struct
import sys
from typing import Union

from internalblue import Address


def bytes_to_hex(data):
    # type: (Union[bytes, bytearray]) -> str
    return "".join(format(x, "02x") for x in bytearray(data))


def p8(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.pack('>B', num)
    elif endian.lower() == 'little':
        return struct.pack('<B', num)
    return struct.pack('B', num)


def p16(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.pack('>H', num)
    elif endian.lower() == 'little':
        return struct.pack('<H', num)
    return struct.pack('H', num)


def u16(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.unpack('>H', num)[0]
    elif endian.lower() == 'little':
        return struct.unpack('<H', num)[0]
    return struct.unpack('H', num)[0]


def p32(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.pack('>I', num)
    elif endian.lower() == 'little':
        return struct.pack('<I', num)
    return struct.pack('I', num)


def u32(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.unpack('>I', num)[0]
    elif endian.lower() == 'little':
        return struct.unpack('<I', num)[0]
    return struct.unpack('I', num)[0]


def flat(data: [Address, bytes], filler: int) -> bytes:
    res = bytes()
    last_section_end = 0
    for address in data:
        res += bytes([filler]) * (address - last_section_end)
        res += data[address]
        last_section_end = address + len(data[address])
    return res


def yesno(message):
    selection = input(f"[🦄] {message} [yes/no] ")
    sys.stdout.write(f"\033[F\033[K")

    while True:
        if selection.lower() in ['y', 'yes']:
            sys.stdout.write(f"[🦄] {message} [\033[1myes\033[0m/no] \n")
            return True
        elif selection.lower() in ['n', 'no']:
            sys.stdout.write(f"[🦄] {message} [yes/\033[1mno\033[0m] \n")
            return False
        else:
            selection = input(f"[🦄] {message} [yes/no] ")