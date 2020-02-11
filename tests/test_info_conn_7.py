from internalblue.cli import _parse_argv
from internalblue.adbcore import ADBCore

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass


def test_info_conn_7():
    dummy = {
        'connection_handle': 0xc,
        'connection_number': 7,
        'master_of_connection': True,
        'remote_name_address': 0,
        'remote_address': '0023023a1a2e'.decode('hex'),
        'id': '00'.decode('hex'),
        'public_rand': 'e98a5eaaff39ecb5ce4447590dfb73a4'.decode('hex'),
        'extended_lmp_feat': '0a00c821ffff8ffa'.decode('hex'),
        'link_key': 'dbea2d9c47bc1aa6afe664ff31591aa6'.decode('hex'),
        'tx_pwr_lvl_dBm': -87,
        'effective_key_len': 16,
        'host_supported_feat': '9bff598701000000'.decode('hex')
    }

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

    nose.tools.assert_dict_equal(information, dummy)

    reference.shutdown()
