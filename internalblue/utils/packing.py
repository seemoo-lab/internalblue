import struct


def p8(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.pack('>B', num)
    elif endian.lower() == 'little':
        return struct.pack('<B', num)
    return struct.pack('B', num)


def u8(num, endian: str = ''):
    if endian.lower() == 'big':
        return struct.unpack('>B', num)[0]
    elif endian.lower() == 'little':
        return struct.unpack('<B', num)[0]
    return struct.unpack('B', num)[0]


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


def bits(s, endian='big') -> [int]:
    """bits(s, endian = 'big', zero = 0, one = 1) -> list

    Converts the argument a list of bits.

    Arguments:
        s: A string or number to be converted into bits.
        endian (str): The binary endian, default 'big'.

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
                byte.append(1 if b & 1 else 0)
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


def bits_str(s, endian='big') -> str:
    """bits_str(s, endian = 'big') -> str
    A wrapper around :func:`bits`, which converts the output into a string.
    Examples:
       >>> bits_str(511)
       '0000000111111111'
       >>> bits_str(b"bits_str", endian = "little")
       '0100011010010110001011101100111011111010110011100010111001001110'
    """
    return ''.join(map(lambda x: str(x), bits(s, endian)))
