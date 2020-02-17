from __future__ import print_function
from internalblue.cli import _parse_argv
from internalblue.adbcore import ADBCore
from internalblue.objects.connection_information import ConnectionInformation

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
    from internalblue import DeviceTuple
except ImportError:
    pass


def test_info_conn_7():
    dummy = ConnectionInformation(7, bytearray.fromhex('0023023a1a2e'), 0, True, 0xc,
                                  bytearray.fromhex('e98a5eaaff39ecb5ce4447590dfb73a4'), 16,
                                  bytearray.fromhex('dbea2d9c47bc1aa6afe664ff31591aa6'), -87,
                                  bytearray.fromhex('0a00c821ffff8ffa'), bytearray.fromhex('9bff598701000000'),
                                  bytearray.fromhex('00'))

    trace = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'traces/adbcore/dictionary_tests/info_conn_7.trace')
    args = _parse_argv('')
    args.device = 'adb_replay'
    args.replay = trace

    data_directory = os.path.expanduser('~') + '/.internalblue'

    if not os.path.exists(data_directory):
        os.mkdir(data_directory)

    from internalblue.socket_hooks import hook, ReplaySocket
    hook(ADBCore, ReplaySocket, filename=args.replay)

    connection_methods = [ADBCore(log_level='info', data_directory=data_directory, replay=True)]

    devices = []  # type: List[DeviceTuple]
    devices = connection_methods[0].device_list()

    device = devices[0]
    reference = device[0]
    reference.interface = device[1]
    reference.connect()

    information = reference.readConnectionInformation(7)
    print(information)

    nose.tools.assert_dict_equal(vars(information), vars(dummy))

    reference.shutdown()
