def bytes_to_hex(bytes):
    # type: (bytearray) -> str
    return ''.join(format(x, '02x') for x in bytearray(bytes))