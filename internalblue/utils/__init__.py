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


def bits(s, endian='big', zero=0, one=1):
    """bits(s, endian = 'big', zero = 0, one = 1) -> list

    Converts the argument a list of bits.

    Arguments:
        s: A string or number to be converted into bits.
        endian (str): The binary endian, default 'big'.
        zero: The representing a 0-bit.
        one: The representing a 1-bit.

    Returns:
        A list consisting of the values specified in `zero` and `one`.

    [!!!] Copied from PWN, only available for bytes.
    """

    if endian not in ['little', 'big']:
        raise ValueError("bits(): 'endian' must be either 'little' or 'big'")
    else:
        little = endian == 'little'

    out = []
    if isinstance(s, bytes):
        for b in bytearray(s):
            byte = []
            for _ in range(8):
                byte.append(one if b & 1 else zero)
                b >>= 1
            if little:
                out += byte
            else:
                out += byte[::-1]
    else:
        raise ValueError("bits(): 's' must be either a string or a number")

    return out


def unbits(s, endian='big'):
    """unbits(s, endian = 'big') -> str

    Converts an iterable of bits into a string.

    Arguments:
       s: Iterable of bits
       endian (str):  The string "little" or "big", which specifies the bits endianness.

    Returns:
       A string of the decoded bits.

    [!!!] Coped from  PWN.
    """
    if endian == 'little':
        u = lambda s: p8(int(s[::-1], 2))
    elif endian == 'big':
        u = lambda s: p8(int(s, 2))
    else:
        raise ValueError("unbits(): 'endian' must be either 'little' or 'big'")

    out = b''
    cur = b''

    for c in s:
        if c in ['1', 1, True]:
            cur += b'1'
        elif c in ['0', 0, False]:
            cur += b'0'
        else:
            raise ValueError("unbits(): cannot decode the value %r into a bit" % c)

        if len(cur) == 8:
            out += u(cur)
            cur = b''
    if cur:
        out += u(cur.ljust(8, b'0'))

    return out


class needs_pwnlibs(object):
    def __init__(self, func):
        self.__name__ = 'dec'
        self.func = func

    def __call__(self, *args, **kwargs):
        if "context" not in self.func.__globals__:
            from pwnlib import context
            from pwnlib.asm import disasm, asm
            from pwnlib.exception import PwnlibException
            context.context.arch = 'thumb'
            self.func.__globals__["context"] = context
            self.func.__globals__["asm"] = asm
            self.func.__globals__["disasm"] = disasm
            self.func.__globals__["PwnlibException"] = PwnlibException
        return self.func(*args, **kwargs)
