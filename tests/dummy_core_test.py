import unittest

from internalblue.testcore import testCore


class DummyCoreTest(unittest.TestCase):

    def setUp(self):
        t = testCore(log_level='debug', data_directory='/tmp')
        dev = t.device_list()[0]
        reference = dev[0]
        reference.interface = dev[1]
        self.assert_(reference.connect(), 'Connect failed')
        self.reference = reference

    def tearDown(self):
        self.reference.shutdown()