from internalblue.cli import _parse_argv
from internalblue.adbcore import ADBCore

import os
import nose

try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple
except ImportError:
    pass


def test_info_heap_old():
    dummy = [
        {
            'index':0,
            'buffer_headers': {
                2194080: 0,
                2193828: 2121160,
                2193864: 2194008,
                2193900: 2194044,
                2193936: 2193864,
                2193972: 2121160,
                2194008: 2193900,
                2194044: 2194080
            },
            'capacity': 8,
            'address': 2121160,
            'next': 2121208,
            'memory_size': 288,
            'waitlist_length': 0,
            'buffer_list': 2193828,
            'memory': 2193828,
            'buffer_size': 32,
            'prev': 2157672,
            'list_length': 7,
            'thread_waitlist': 0
        },
        {
            'index': 1,
            'buffer_headers': {
                2194592: 0,
                2194116: 2194184,
                2194184: 2194252,
                2194252: 2194320,
                2194320: 2194388,
                2194388: 2194456,
                2194456: 2194524,
                2194524: 2194592
            },
            'capacity': 8,
            'address': 2121208,
            'next': 2121256,
            'memory_size': 544,
            'waitlist_length': 0,
            'buffer_list': 2194184,
            'memory': 2194116,
            'buffer_size': 64,
            'prev': 2121160,
            'list_length': 7,
            'thread_waitlist': 0
        },
        {
            'index': 2,
            'buffer_headers': {
                2196000: 2196268,
                2197072: 0,
                2194660: 2194928,
                2195464: 2195732,
                2196268: 2196536,
                2194928: 2195196,
                2195732: 2196000,
                2196536: 2196804,
                2196804: 2197072,
                2195196: 2195464
            },
            'capacity': 10,
            'address': 2121256,
            'next': 2121352,
            'memory_size': 2680,
            'waitlist_length': 0,
            'buffer_list': 2194660,
            'memory': 2194660,
            'buffer_size': 264,
            'prev': 2121208,
            'list_length': 10,
            'thread_waitlist': 0
        },
        {
            'index': 3,
            'buffer_headers': {
                2214480: 2215548,
                2215548: 2216616,
                2216616: 0,
                2213412: 2214480
            },
            'capacity': 4,
            'address': 2121352,
            'next': 2121304,
            'memory_size': 4272,
            'waitlist_length': 0,
            'buffer_list': 2213412,
            'memory': 2213412,
            'buffer_size': 1064,
            'prev': 2121256,
            'list_length': 4,
            'thread_waitlist': 0
        },
        {
            'index': 4,
            'buffer_headers': {
                2234124: 0,
                2231932: 2233028,
                2224260: 2225356,
                2219876: 2220972,
                2226452: 2227548,
                2223164: 2224260,
                2228644: 2229740,
                2220972: 2222068,
                2225356: 2226452,
                2230836: 2231932,
                2233028: 2234124,
                2222068: 2223164,
                2227548: 2228644,
                2217684: 2218780,
                2218780: 2219876,
                2229740: 2230836
            },
            'capacity': 16,
            'address': 2121304,
            'next': 2157624,
            'memory_size': 17536,
            'waitlist_length': 0,
            'buffer_list': 2217684,
            'memory': 2217684,
            'buffer_size': 1092,
            'prev': 2121352,
            'list_length': 16,
            'thread_waitlist': 0
        },
        {
            'index': 5,
            'buffer_headers': {
                2235264: 2235308,
                2235616: 2235660,
                2235396: 2235440,
                2235528: 2235572,
                2235660: 2235704,
                2235308: 2235352,
                2235440: 2235484,
                2235704: 2235748,
                2235792: 2235836,
                2235220: 2235264,
                2235748: 2235792,
                2235352: 2235396,
                2235572: 2235616,
                2235836: 0,
                2235484: 2235528
            },
            'capacity': 15,
            'address': 2157624,
            'next': 2157672,
            'memory_size': 660,
            'waitlist_length': 0,
            'buffer_list': 2235220,
            'memory': 2235220,
            'buffer_size': 40,
            'prev': 2121304,
            'list_length': 15,
            'thread_waitlist': 0
        },
        {
            'index': 6,
            'buffer_headers': {
                2236096: 2236132,
                2236240: 2236276,
                2236132: 2236168,
                2236384: 0,
                2235880: 2235916,
                2236204: 2236240,
                2236348: 2236384,
                2235916: 2235952,
                2235952: 2235988,
                2236168: 2236204,
                2236312: 2236348,
                2235988: 2236024,
                2236024: 2236060,
                2236276: 2236312,
                2236060: 2236096
            },
            'capacity': 15,
            'address': 2157672,
            'next': 2121160,
            'memory_size': 540,
            'waitlist_length': 0,
            'buffer_list': 2235880,
            'memory': 2235880,
            'buffer_size': 32,
            'prev': 2157624,
            'list_length': 15,
            'thread_waitlist': 0
        }]

    trace = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'traces/adbcore/dictionary_tests/info_heap_old.trace')
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

    information = reference.readHeapInformation()
    print(information)

    nose.tools.assert_equal(information, dummy)

    reference.shutdown()