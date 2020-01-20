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





if __name__ == '__main__':
    test_all_traces()