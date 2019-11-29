import nose







from .dummy_core_test import DummyCoreTest
from internalblue.cmds import CmdHexdump, CmdSendHciCmd

import unittest


class TestCmdSendHciCmd(DummyCoreTest):
    def test_version(self):

        cmd = CmdSendHciCmd("sendhcicmd 0x1001", self.reference)
        result = cmd.work()
        nose.tools.assert_equal(result, b'\x01\x01\x10\x00\x06\xb4\x15\x06\x0f\x00\x0e"')
        pass

    def test_write(self):
        cmd = CmdSendHciCmd("sendhcicmd 0xfc4c", self.reference)
        pass
        #cmd.readMem()


if __name__ == '__main__':
    unittest.main()

