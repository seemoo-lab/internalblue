import sys
from typing import Union

from internalblue import Address


def bytes_to_hex(data):
    # type: (Union[bytes, bytearray]) -> str
    return "".join(format(x, "02x") for x in bytearray(data))


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
