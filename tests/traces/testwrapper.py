from builtins import object
import argparse

from internalblue.cli import internalblue_cli, _parse_argv

import os

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass


tracedir = os.path.dirname(__file__)


class Fakeargs(object):
    def __init__(self):
        self.data_directory = None
        self.verbose = False
        self.trace = None
        self.save = None
        self.replay = None
        self.device = ""
        self.ios_device = False
        self.testdevice = False


def _device_to_core():
    pass

core_to_device = {
    'hcicore': 'hci_replay',
    'macoscore': 'macos_replay',
    'adbcore': 'adb_replay'
}

def get_trace_path_cmd_tuple(core, tracefile):
    # type: (str, str) -> Tuple[str, Optional[str]]
    tracepath = os.path.join(tracedir, core, tracefile)
    with open(tracepath) as f:
        cmd = f.readline()
    if cmd.startswith("#"):
        return tracepath, cmd[1:]
    else:
        return tracepath, None



def trace_test(core, tracepath, commands):
    args = _parse_argv("")
    args.device = core_to_device[core]
    args.replay = tracepath
    args.commands = commands + "; quit"
    internalblue_cli("", args=args)




if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--core")
    parser.add_argument("--trace")
    parser.add_argument("--commands")
    args = parser.parse_args()

    tracepath, commands = get_trace_path_cmd_tuple(args.core, args.trace)
    trace_test(args.core, tracepath, commands)