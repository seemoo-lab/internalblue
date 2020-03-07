# from pwnlib.util.packing import *
from typing import Union


def bytes_to_hex(bytes):
    # type: (Union[bytes, bytearray]) -> str
    return "".join(format(x, "02x") for x in bytearray(bytes))
