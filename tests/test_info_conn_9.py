from internalblue.cli import _parse_argv
from internalblue.adbcore import ADBCore
from internalblue.objects.connection_information import Connection_Information

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass


def test_info_conn_9():
    dummy = Connection_Information(9, '000000000000'.decode('hex'), 0, False, 12,
        '00000000000000000000000000000000'.decode('hex'), 0, '', -87, '0000000000000000'.decode('hex'),
        '0000000000000000'.decode('hex'), '00'.decode('hex'))

    trace = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'traces/adbcore/dictionary_tests/info_conn_9.trace')
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

    information = reference.readConnectionInformation(9)
    print(information)

    nose.tools.assert_dict_equal(vars(information), vars(dummy))

    reference.shutdown()
