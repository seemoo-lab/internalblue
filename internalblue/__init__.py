from future import standard_library

standard_library.install_aliases()

import datetime

from queue import Queue
from typing import (
    List,
    Optional,
    Any,
    TYPE_CHECKING,
    Tuple,
    Union,
    NewType,
    Callable,
    Dict,
)

Address = NewType("Address", int)
ConnectionNumber = NewType("ConnectionNumber", int)
ConnectionIndex = NewType("ConnectionIndex", int)

BluetoothAddress = NewType("BluetoothAddress", bytes)
ConnectionDict = NewType("ConnectionDict", Dict[str, Any])
HeapInformation = NewType("HeapInformation", Dict[str, Any])
QueueInformation = NewType("QueueInformation", Dict[str, Any])
QueueInformation = NewType("MemoryPool", Dict[str, Any])

try:

    if TYPE_CHECKING:
        from internalblue.hci import HCI
        from internalblue.core import InternalBlue

        Record = Tuple[HCI, int, int, int, Any, datetime.datetime]
        FilterFunction = Callable[[Record], bool]

        Opcode = NewType("Opcode", int)
        HCI_CMD = NewType("HCI_CMD", int)
        Task = Tuple[HCI_CMD, bytes, Queue, Callable[[Record], bool]]

        Device = NewType("Device", Dict[str, Any])
        """{"dev_id": dev_id,
         "dev_name": dev_name,
         "dev_bdaddr": dev_bdaddr,
         "dev_flags": dev_flags,
         "dev_flags_str": dev_flags_str}"""
        # InternalBlueCore, Device Name, SomeString
        DeviceTuple = Tuple[InternalBlue, str, str]


except:
    pass
