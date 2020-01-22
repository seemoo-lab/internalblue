from testwrapper import test_trace, get_trace_path_cmd_tuple


import os
tracedir = os.path.join(os.path.dirname(__file__), "traces")

#cores = ['macoscore', 'ioscore', 'adbcore', 'hcicore']

def test_all_traces():
    cores = os.listdir(tracedir)
    for core in cores:
        for tracefile in os.listdir(os.path.join(tracedir, core)):

                tracepath, cmd = get_trace_path_cmd_tuple(core, tracefile)
                if cmd:
                    print("Running trace {} on core {} with cmds {}".format(tracefile, core, cmd))
                    test_trace(core, tracepath, cmd)
                else:
                    print("Skipping trace {} because it has no commands specified".format(tracefile))



import unittest


def generate_test_suite():

    def generate_test_from_file(core, tracefile):
        tracepath, cmd = get_trace_path_cmd_tuple(core, tracefile)

        def test():
            test_trace(core, tracepath, cmd)

        # Rename the function to the tracefile name without .trace suffix
        test.__name__ = tracefile[:-6]
        if cmd:
            return test
        else:
            return unittest.skip("No command specified in trace {}".format(tracepath))(test)

    suite = unittest.TestSuite()
    for core in os.listdir(tracedir):
        core_suite = unittest.TestSuite()
        for tracefile in os.listdir(os.path.join(tracedir, core)):
            if tracefile != '.gitkeep':
                core_suite.addTest(
                    unittest.FunctionTestCase(generate_test_from_file(core, tracefile), description=tracefile))
        suite.addTest(core_suite)

    return suite
    # test_all_traces()



if __name__ == '__main__':
    suite = generate_test_suite()
    unittest.TextTestRunner().run(suite)
