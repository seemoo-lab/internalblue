"""
The following proxies various utilities from pwnlibs by explicitly importing them
To replace a "from pwn import *" remove it and let your IDE highlight all missing methods (Hint: F2 in PyCharm goes to next error)
import the missing (and only the missing!) methods from this module, e.g. with "from internalblue.utils import term, read, log, text, options"
In some cases like "from pwn import socket" this just imports another module.
Use an IPython shell to run "from pwn import *" and check where some method/module actually comes from and either import it directly or add it to this module
"""



# Imports that used to be imported via 'from pwn import *'

from pwnlib.util import iters
from pwnlib import term
from pwnlib.util.misc import read
from pwnlib.context import context
import pwnlib.log
log = pwnlib.log.getLogger('internalbue')
from pwnlib.term import text
from pwnlib.ui import options, yesno
from pwnlib.util.packing import flat
from pwnlib.asm import disasm
from pwnlib.util.fiddling import isprint, unbits, bits_str, bits




"""
The packers like u8 are generated in a fairly convoluted way that breaks IDE introspection.
The following code remedies this by:
- Explicitly defining a stub function with type annotations
- Generating all the packers like pwnlibs would
- Only if if the current module already has the name of the packer as an attribute (i.e. has a stub function defined) it will be replaced with the pwnlibs version

This means:
- All import issues in the rest of the code are genuine as the imports are only available if an explicit stub function is added
- The functions can be easily replaced by just implementing them and removing the for loop at the end

"""

# Imports needed for this hack
from pwnlib.util.packing import ops, sizes, make_multi
import sys
from typing import Union, Optional, Literal
mod = sys.modules[__name__]


_DEFINES = ['u8', 'p8', 'u32', 'u16', 'p32']

endianess = Union[Literal['big']]

def u8(data: bytes, endian: Optional[endianess] = None) -> int: ...
def p8(number: int, endian: Optional[endianess] = None) -> bytes: ...
def u16(data: bytes, endian: Optional[endianess] = None) -> int: ...
def p16(number: int, endian: Optional[endianess] = None) -> bytes: ...
def u32(data: bytes, endian: Optional[endianess] = None) -> int: ...
def p32(number: int, endian: Optional[endianess] = None) -> bytes: ...


for op, size in iters.product(ops, sizes):
    name, routine = make_multi(op, size)
    if hasattr(mod, name):
        setattr(mod, name, routine)