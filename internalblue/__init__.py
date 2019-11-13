
try:
    from Queue import Queue
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple, Union, NewType, Callable, Dict
    import datetime
    from internalblue.hci import HCI
    Address = NewType("Address", int)
    Record = Tuple[HCI, int, int, int, Any, datetime.datetime]
    FilterFunction = NewType("FilterFunction", Callable[[Record], bool])
    ConnectionNumber = NewType("ConnectionNumber", int)
    ConnectionIndex = NewType("ConnectionIndex", int)

    BluetoothAddress = NewType("BluetoothAddress", bytes)
    ConnectionDict = NewType("ConnectionDict", Dict[str,Any])
    HeapInformation = NewType("HeapInformation", Dict[str, Any])
    QueueInformation = NewType('QueueInformation', Dict[str, Any])
    Opcode = NewType('Opcode', int)
    HCI_CMD = NewType('HCI_CMD', int)
    Task = Tuple[HCI_CMD, bytes, Queue.Queue, Callable[[Record], bool]]
    if TYPE_CHECKING:
        pass
except:
    pass
