from builtins import object
import argparse

from internalblue.cli import InternalBlueCLI, parse_args

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
        return tracepath, cmd[1:-1]
    else:
        return tracepath, None


def trace_test(core, tracepath, commands):
    args, unknown_args = parse_args()
    args.device = core_to_device[core]
    args.replay = tracepath
    cli = InternalBlueCLI(args)
    cmd_array = commands.split("; ")
    if "quit" not in cmd_array[len(cmd_array)-1]:
        cmd_array += "quit"
    cli.runcmds_plus_hooks(cmd_array)

# TODO: - Running individual tests with this method is currently a bit broken
# if __name__ == '__main__':
    # parser = argparse.ArgumentParser()
    # parser.add_argument("--core")
    # parser.add_argument("--trace")
    # parser.add_argument("--commands")
    # margs = parser.parse_args()
    #
    # tracepath, commands = get_trace_path_cmd_tuple(margs.core, margs.trace)
    # print(tracepath)
    # print(commands)
    # trace_test(margs.core, tracepath, commands)
