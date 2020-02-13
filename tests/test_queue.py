from internalblue.cli import _parse_argv
from internalblue.adbcore import ADBCore

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass


def test_info_queue():
    dummy = [
        {
          'index': 0,
          'next_item': 2123268,
          'prev': 2141676,
          'capacity': 16,
          'name': 'tran_HCIEvent',
          'queue_buf_start': 2123208,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2123268,
          'free_slots': 16,
          'address': 2123152,
          'waitlist_length': 0,
          'next': 2123332,
          'queue_buf_end': 2123272,
          'thread_waitlist': 0
       },
       {
          'index': 1,
          'next_item': 2123436,
          'prev': 2123152,
          'capacity': 31,
          'name': 'tran_ACLData',
          'queue_buf_start': 2123388,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2123436,
          'free_slots': 31,
          'address': 2123332,
          'waitlist_length': 0,
          'next': 2123636,
          'queue_buf_end': 2123636,
          'thread_waitlist': 0
       },
       {
          'index': 2,
          'next_item': 2123692,
          'prev': 2123332,
          'capacity': 3,
          'name': 'tran_SCOData',
          'queue_buf_start': 2123692,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2123692,
          'free_slots': 3,
          'address': 2123636,
          'waitlist_length': 0,
          'next': 2123704,
          'queue_buf_end': 2123704,
          'thread_waitlist': 0
       },
       {
          'index': 3,
          'next_item': 2123760,
          'prev': 2123636,
          'capacity': 31,
          'name': 'tran_UartBridgeNonHCIEvent',
          'queue_buf_start': 2123760,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2123760,
          'free_slots': 31,
          'address': 2123704,
          'waitlist_length': 0,
          'next': 2123884,
          'queue_buf_end': 2123884,
          'thread_waitlist': 0
       },
       {
          'index': 4,
          'next_item': 2124000,
          'prev': 2123704,
          'capacity': 20,
          'name': 'tran_DiagData',
          'queue_buf_start': 2123940,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2124000,
          'free_slots': 20,
          'address': 2123884,
          'waitlist_length': 0,
          'next': 2124020,
          'queue_buf_end': 2124020,
          'thread_waitlist': 0
       },
       {
          'index': 5,
          'next_item': 2124076,
          'prev': 2123884,
          'capacity': 8,
          'name': 'tran_HIDUsbKBEvt',
          'queue_buf_start': 2124076,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2124076,
          'free_slots': 8,
          'address': 2124020,
          'waitlist_length': 0,
          'next': 2124140,
          'queue_buf_end': 2124140,
          'thread_waitlist': 0
       },
       {
          'index': 6,
          'next_item': 2124196,
          'prev': 2124020,
          'capacity': 6,
          'name': 'tran_HIDUsbMSEvt',
          'queue_buf_start': 2124196,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2124196,
          'free_slots': 6,
          'address': 2124140,
          'waitlist_length': 0,
          'next': 2124244,
          'queue_buf_end': 2124244,
          'thread_waitlist': 0
       },
       {
          'index': 7,
          'next_item': 2100496,
          'prev': 2124140,
          'capacity': 1,
          'name': 'tran_HIDUsbMSCtrl',
          'queue_buf_start': 2100496,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2100496,
          'free_slots': 1,
          'address': 2124244,
          'waitlist_length': 0,
          'next': 2124300,
          'queue_buf_end': 2100504,
          'thread_waitlist': 0
       },
       {
          'index': 8,
          'next_item': 2100504,
          'prev': 2124244,
          'capacity': 1,
          'name': 'tran_HIDUsbKBCtrl',
          'queue_buf_start': 2100504,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2100504,
          'free_slots': 1,
          'address': 2124300,
          'waitlist_length': 0,
          'next': 2124356,
          'queue_buf_end': 2100512,
          'thread_waitlist': 0
       },
       {
          'index': 9,
          'next_item': 2124412,
          'prev': 2124300,
          'capacity': 32,
          'name': 'tran_HidAuxData',
          'queue_buf_start': 2124412,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2124412,
          'free_slots': 32,
          'address': 2124356,
          'waitlist_length': 0,
          'next': 2110352,
          'queue_buf_end': 2124668,
          'thread_waitlist': 0
       },
       {
          'index': 10,
          'next_item': 2192300,
          'prev': 2124356,
          'capacity': 12,
          'name': 'lm_Cmd',
          'queue_buf_start': 2192284,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2192300,
          'free_slots': 12,
          'address': 2110352,
          'waitlist_length': 0,
          'next': 2120560,
          'queue_buf_end': 2192380,
          'thread_waitlist': 0
       },
       {
          'index': 11,
          'next_item': 2192400,
          'prev': 2110352,
          'capacity': 8,
          'name': 'hci_HciCommand',
          'queue_buf_start': 2192380,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2192400,
          'free_slots': 8,
          'address': 2120560,
          'waitlist_length': 0,
          'next': 2110408,
          'queue_buf_end': 2192412,
          'thread_waitlist': 0
       },
       {
          'index': 12,
          'next_item': 2192412,
          'prev': 2120560,
          'capacity': 19,
          'name': 'lm_deferredAction',
          'queue_buf_start': 2192412,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2192412,
          'free_slots': 19,
          'address': 2110408,
          'waitlist_length': 0,
          'next': 2118068,
          'queue_buf_end': 2192564,
          'thread_waitlist': 0
       },
       {
          'index': 13,
          'next_item': 2192564,
          'prev': 2110408,
          'capacity': 6,
          'name': 'lrmmsm_cmd',
          'queue_buf_start': 2192564,
          'available_items': 0,
          'item_size': 8,
          'next_free_slot': 2192564,
          'free_slots': 6,
          'address': 2118068,
          'waitlist_length': 0,
          'next': 2141588,
          'queue_buf_end': 2192612,
          'thread_waitlist': 0
       },
       {
          'index': 14,
          'next_item': 2141644,
          'prev': 2118068,
          'capacity': 8,
          'name': 'liteHostEvent',
          'queue_buf_start': 2141644,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2141644,
          'free_slots': 8,
          'address': 2141588,
          'waitlist_length': 0,
          'next': 2141676,
          'queue_buf_end': 2141676,
          'thread_waitlist': 0
       },
       {
          'index': 15,
          'next_item': 2141732,
          'prev': 2141588,
          'capacity': 16,
          'name': 'litehostRcvdL2capData',
          'queue_buf_start': 2141732,
          'available_items': 0,
          'item_size': 4,
          'next_free_slot': 2141732,
          'free_slots': 16,
          'address': 2141676,
          'waitlist_length': 0,
          'next': 2123152,
          'queue_buf_end': 2141796,
          'thread_waitlist': 0
       }
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

    nose.tools.assert_equal(information, dummy)

    reference.shutdown()