from internalblue.cli import _parse_argv
from internalblue.adbcore import ADBCore
from internalblue.objects.queue_element import QueueElement

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass

def test_info_queue():
    dummy = [
        QueueElement(0, 2123152, 4, 16, 0, 16, 2123208, 2123272, 2123268, 2123268, 0, 0, 2123332, 2141676, 'tran_HCIEvent'),
        QueueElement(1, 2123332, 8, 31, 0, 31, 2123388, 2123636, 2123436, 2123436, 0, 0, 2123636, 2123152, 'tran_ACLData'),
        QueueElement(2, 2123636, 4, 3, 0, 3, 2123692, 2123704, 2123692, 2123692, 0, 0, 2123704, 2123332, 'tran_SCOData'),
        QueueElement(3, 2123704, 4, 31, 0, 31, 2123760, 2123884, 2123760, 2123760, 0, 0, 2123884, 2123636, 'tran_UartBridgeNonHCIEvent'),
        QueueElement(4, 2123884, 4, 20, 0, 20, 2123940, 2124020, 2124000, 2124000, 0, 0, 2124020, 2123704, 'tran_DiagData'),
        QueueElement(5, 2124020, 8, 8, 0, 8, 2124076, 2124140, 2124076, 2124076, 0, 0, 2124140, 2123884, 'tran_HIDUsbKBEvt'),
        QueueElement(6, 2124140, 8, 6, 0, 6, 2124196, 2124244, 2124196, 2124196, 0, 0, 2124244, 2124020, 'tran_HIDUsbMSEvt'),
        QueueElement(7, 2124244, 8, 1, 0, 1, 2100496, 2100504, 2100496, 2100496, 0, 0, 2124300, 2124140, 'tran_HIDUsbMSCtrl'),
        QueueElement(8, 2124300, 8, 1, 0, 1, 2100504, 2100512, 2100504, 2100504, 0, 0, 2124356, 2124244, 'tran_HIDUsbKBCtrl'),
        QueueElement(9, 2124356, 8, 32, 0, 32, 2124412, 2124668, 2124412, 2124412, 0, 0, 2110352, 2124300, 'tran_HidAuxData'),
        QueueElement(10, 2110352, 8, 12, 0, 12, 2192284, 2192380, 2192300, 2192300, 0, 0, 2120560, 2124356, 'lm_Cmd'),
        QueueElement(11, 2120560, 4, 8, 0, 8, 2192380, 2192412, 2192400, 2192400, 0, 0, 2110408, 2110352, 'hci_HciCommand'),
        QueueElement(12, 2110408, 8, 19, 0, 19, 2192412, 2192564, 2192412, 2192412, 0, 0, 2118068, 2120560, 'lm_deferredAction'),
        QueueElement(13, 2118068, 8, 6, 0, 6, 2192564, 2192612, 2192564, 2192564, 0, 0, 2141588, 2110408, 'lrmmsm_cmd'),
        QueueElement(14, 2141588, 4, 8, 0, 8, 2141644, 2141676, 2141644, 2141644, 0, 0, 2141676, 2118068, 'liteHostEvent'),
        QueueElement(15, 2141676, 4, 16, 0, 16, 2141732, 2141796, 2141732, 2141732, 0, 0, 2123152, 2141588, 'litehostRcvdL2capData')
    ]

    trace = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'traces/adbcore/dictionary_tests/info_queue.trace')
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

    information = reference.readQueueInformation()
    print(information)

    nose.tools.assert_equal([vars(element) for element in information], [vars(element) for element in dummy])

    reference.shutdown()