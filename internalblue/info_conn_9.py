from internalblue.cli import _parse_argv
from .adbcore import ADBCore

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass


dummy = {
    'connection_handle': 12,
    'connection_number': 9,
    'master_of_connection': False,
    'remote_name_address': 0,
    'remote_address':'000000000000'.decode('hex'),
    'id': '00'.decode('hex'),
    'public_rand':'00000000000000000000000000000000'.decode('hex'),
    'extended_lmp_feat':'0000000000000000'.decode('hex'),
    'link_key': '',
    'tx_pwr_lvl_dBm': -87,
    'effective_key_len': 0,
    'host_supported_feat':'0000000000000000'.decode('hex')
}

args = _parse_argv('')
args.device = 'adb_replay'
args.replay = 'tests/traces/adbcore/info_conn_9.trace'

data_directory = os.path.expanduser('~') + '/.internalblue'

if not os.path.exists(data_directory):
    os.mkdir(data_directory)

from .socket_hooks import hook, ReplaySocket
hook(ADBCore, ReplaySocket, filename=args.replay)

connection_methods = [ADBCore(log_level='info', data_directory=data_directory, replay=True)]

devices = [] # type: List[DeviceTuple]
devices = connection_methods[0].device_list()

device = devices[0]
reference = device[0]
reference.interface = device[1]
reference.connect()

information = reference.readConnectionInformation(9)
print(information)

nose.tools.assert_dict_equal(information, dummy)

reference.shutdown()
