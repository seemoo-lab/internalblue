import nose



try:
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from internalblue import Address
except ImportError:
    Address = lambda x: x
    pass



from .dummy_core_test import DummyCoreTest
from internalblue.cmds import CmdHexdump


import unittest


class TestDirectMemReadWrite(DummyCoreTest):

    def test_read_mem(self):
        from internalblue.cmds import CmdHexdump
        hdxdmp = CmdHexdump("hexdump 0xc0 -l 0x20", self.reference)
        dump = hdxdmp.readMem(Address(0xc0), 0x20)
        nose.tools.assert_equal(dump, b'\\\x01\x00\x00-.\x03\x00Copyright (c) Broadcom C')


    def test_write_mem(self):
        from internalblue.cmds import CmdWriteMem
        cmd = CmdWriteMem("writemem --hex 0xc0 41424344", self.reference)
        data = b'FOOBAR'
        status = cmd.writeMem(Address(0x1000), data)
        nose.tools.assert_true(status)

        read = cmd.readMem(Address(0x1000), len(data))

        nose.tools.assert_equal(data, read)


if __name__ == '__main__':
    unittest.main()

