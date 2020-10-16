from __future__ import print_function
from __future__ import absolute_import

from tests.traces.testwrapper import trace_test, get_trace_path_cmd_tuple
import unittest
import os
tracedir = os.path.dirname(__file__)


def generate_test_suite_from_traces():

    def generate_test_from_file(core, tracefile):
        tracepath, cmd = get_trace_path_cmd_tuple(core, tracefile)

        def test():
            print("Running test %s " % (tracefile[:-6]))
            trace_test(core, tracepath, cmd)

        # Rename the function to the tracefile name without .trace suffix
        test.__name__ = tracefile[:-6]
        if cmd:
            return test
        else:
            return unittest.skip("No command specified in trace {}".format(tracepath))(test)

    suite = unittest.TestSuite()
    for core in os.listdir(tracedir):
        if os.path.isdir(os.path.join(tracedir,core)):
            core_suite = unittest.TestSuite()
            for tracefile in os.listdir(os.path.join(tracedir, core)):
                if tracefile.endswith(".trace"):
                    core_suite.addTest(
                        unittest.FunctionTestCase(generate_test_from_file(core, tracefile), description=tracefile))
            suite.addTest(core_suite)

    return suite
    # test_all_traces()

def load_tests(loader, standard_tests, n):
    """
    This method is called by test frameworks to supply a testsuite instead of the test framework collecting them itself.
    This allows use to automatically generate a proper test for each trace in the subdirectory that has a command specified.
    Those tests are then run by the framework in the usual way which integrates with IDEs
    TODO: Document PyCharm Setup
    """

    trace_suite = generate_test_suite_from_traces()
    return trace_suite

if __name__ == '__main__':
    suite = generate_test_suite_from_traces()
    unittest.TextTestRunner().run(suite)



