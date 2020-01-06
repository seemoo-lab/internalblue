
try:
    from Queue import Queue
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple, Union, NewType, Callable, Dict

    if TYPE_CHECKING:
        import datetime
        from internalblue.hci import HCI
        from internalblue.core import InternalBlue
        Address = NewType("Address", int)
        Record = Tuple[HCI, int, int, int, Any, datetime.datetime]
        FilterFunction = Callable[[Record], bool]
        ConnectionNumber = NewType("ConnectionNumber", int)
        ConnectionIndex = NewType("ConnectionIndex", int)

        BluetoothAddress = NewType("BluetoothAddress", bytes)
        ConnectionDict = NewType("ConnectionDict", Dict[str,Any])
        HeapInformation = NewType("HeapInformation", Dict[str, Any])
        QueueInformation = NewType('QueueInformation', Dict[str, Any])
        Opcode = NewType('Opcode', int)
        HCI_CMD = NewType('HCI_CMD', int)
        Task = Tuple[HCI_CMD, bytes, Queue.Queue, Callable[[Record], bool]]

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


import logging


class ProgressLog():
    """
    Hack to get around the dependency to the pwnlib logger
    This looses functionality, but at some point this can be replaced by something like progressbar2
    """
    def __init__(self, init_msg,logger):
        self.logger = logger
        self.logger.warning(init_msg)

    def failure(self, msg):
        self.logger.warning(msg)

    def status(self, msg):
        self.logger.info(msg)

    def success(self, msg):
        self.logger.info(msg)

def getLogger(name):
    logger = logging.getLogger(name)
    logger.progress = lambda msg: ProgressLog(msg, logger)
    return logger
