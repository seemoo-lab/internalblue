# """
# The following proxies various utilities from pwnlibs by explicitly importing them
# To replace a "from pwn import *" remove it and let your IDE highlight all missing methods (Hint: F2 in PyCharm goes to next error)
# import the missing (and only the missing!) methods from this module, e.g. with "from internalblue.utils import term, read, log, text, options"
# In some cases like "from pwn import socket" this just imports another module.
# Use an IPython shell to run "from pwn import *" and check where some method/module actually comes from and either import it directly or add it to this module
# """
#
#
# # Imports that used to be imported via 'from pwn import *'
# import pwnlib
# from pwnlib import term
# from pwnlib.util import iters
# from pwnlib.util.misc import read
# from pwnlib.context import context
#
# # TODO: Logging via pwnlib doesn't work yet, so for now it is still used via pwn
# # import pwnlib.log
# # pwnlib.log.install_default_handler()
# # log = pwnlib.log.getLogger('internalbue')
#
# from pwn import log
#
#
# from pwnlib.term import text
# from pwnlib.ui import options, yesno
# from pwnlib.util.packing import flat
# from pwnlib.asm import disasm, asm
# from pwnlib.util.fiddling import isprint, unbits, bits_str, bits
#
#
# """
# The packers like u8 are generated in a fairly convoluted way that breaks IDE introspection.
# The following code remedies this by:
# - Explicitly defining a stub function with type annotations
# - Generating all the packers like pwnlibs would
# - Only if if the current module already has the name of the packer as an attribute (i.e. has a stub function defined) it will be replaced with the pwnlibs version
#
# This means:
# - All import issues in the rest of the code are genuine as the imports are only available if an explicit stub function is added
# - The functions can be easily replaced by just implementing them and removing the for loop at the end
#
# """
#
# # Imports needed for this hack
# from pwnlib.util.packing import ops, sizes, make_multi
# import sys
#
# try:
#     from typing import Union, Optional, Literal
#
#     endianess = Union[Literal["big"]]
#
# except ImportError:
#     pass
# mod = sys.modules[__name__]
#
#
# _DEFINES = ["u8", "p8", "u32", "u16", "p32"]
#
#
# def u8(data, endian=None):
#     # type: (bytes, Optional[endianess]) -> int
#     pass
#
#
# def p8(number, endian=None):
#     # type: (int, Optional[endianess]) -> bytes
#     pass
#
#
# def u16(data, endian=None):
#     # type: (bytes, Optional[endianess]) -> int
#     pass
#
#
# def p16(number, endian=None):
#     # type: (int, Optional[endianess]) -> bytes
#     pass
#
#
# def u32(data, endian=None):
#     # type: (bytes, Optional[endianess]) -> int
#     pass
#
#
# def p32(number, endian=None):
#     # type: (int, Optional[endianess]) -> bytes
#     pass
#
#
# for op, size in iters.product(ops, sizes):
#     name, routine = make_multi(op, size)
#     if hasattr(mod, name):
#         setattr(mod, name, routine)
