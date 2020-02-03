import binascii
import time


try:
    from typing import List, Optional, Any, TYPE_CHECKING, Tuple, Dict, Type
except ImportError:
    pass


class SocketRecvHook():
    def __init__(self, socket):
        # type: (socket.socket) -> None
        self.snoop_socket = socket
        self.replace = False

    def recv_hook(self, data):
        raise NotImplementedError("recv_hook not implemented")

    def recv_replace(self, length, **kwargs):
        raise NotImplementedError("recv_replace not implemented")

    def recv(self, length, **kwargs):
        if not self.replace:
            data = self.snoop_socket.recv(length, **kwargs)
        else:
            data = self.recv_replace(length, **kwargs)
        self.recv_hook(data)
        return data

    def recvfrom_replace(self, length, **kwargs):
        raise NotImplementedError("recvfrom_replace not implemented")

    def recvfrom_hook(self, data, addr):
        raise NotImplementedError("recvfrom_hook not implemented")

    def recvfrom(self, length, **kwargs):
        # type: (int, Dict[str, Any]) -> Tuple[bytes, Any]
        if not self.replace:
            data, addr = self.snoop_socket.recvfrom(length)
        else:
            data, addr = self.recvfrom_replace(length, **kwargs)
        self.recvfrom_hook(data, addr)
        return data, addr

class SocketInjectHook():
    def __init__(self, socket, core):
        # type: (socket.socket, InternalBlue) -> None
        self.inject_socket = socket
        self.replace = False
        self.core = core # type: InternalBlue

    def close(self):
        if self.inject_socket:
            self.inject_socket.close()

    def send(self, data):
        self.send_hook(data)
        if not self.replace:
            try:
                self.inject_socket.send(data)
            except Exception as e:
                self.send_exception(e)
                raise e
        else:
            try:
                self.send_replace(data)
            except Exception as e:
                self.core.test_failed = e
                raise

    def sendto(self, data, socket):
        self.sendto_hook(data, socket)
        if not self.replace:
            try:
                self.inject_socket.sendto(data, socket)
            except Exception as e:
                self.send_exception(e)
                raise e
        else:
            try:
                self.send_replace(data)
            except Exception as e:
                self.core.test_failed = e
                raise e

    def getsockname(self):
        return self.snoop_socket.getsockname()

    def send_hook(self, result):
        raise NotImplementedError("send_hook not implemented")

    def sendto_hook(self, data, socket):
        raise NotImplementedError("sendto_hook not implemented")

    def send_replace(self, data):
        raise NotImplementedError("send_replace not implemented")

    def send_exception(self, e):
        raise NotImplementedError("send_exception not implemented")


class SocketDuplexHook(SocketInjectHook, SocketRecvHook):

    def __init__(self, snoop_socket, inject_socket, core, **kwargs):
        # type: (socket.socket, socket.socket, InternalBlue, Dict[str, Any]) -> None
        self.snoop_socket = snoop_socket
        self.inject_socket = inject_socket
        self.replace = False
        self.core = core

    pass


class HookBase():
    def send_hook(self, data):
        raise NotImplementedError

    def recv_hook(self, data):
        raise NotImplementedError


class TraceToFileHook(SocketDuplexHook):
    def __init__(self, snoop_socket, inject_socket, core, filename='/tmp/bt_hci.log'):
        # type: (socket.socket, socket.socket, InternalBlue, str) -> None
        SocketDuplexHook.__init__(self, snoop_socket, inject_socket, core)
        self.file = open(filename, 'a')
        self.replace = False
        self.log = []
        self.closed = False

    def recv_hook(self, data):
        line = "RX {}\n".format(binascii.hexlify(data))
        print(line)
        self.log.append(line)

    def send_hook(self, data):
        line = "TX {}\n".format(binascii.hexlify(data))
        print(line)
        self.log.append(line)

    def recvfrom_hook(self, data, socket, **kwargs):
        line = "RX {}\n".format(binascii.hexlify(data))
        print(line)
        self.log.append(line)

    def sendto_hook(self, data, socket, **kwargs):
        line = "TX {}\n".format(binascii.hexlify(data))
        print(line)
        self.log.append(line)

    def send_exception(self, e):
        line = "EX '{}'\n".format(e)
        print(line)
        self.log.append(line)

    def close(self):
        if not self.closed:
            self.inject_socket.close()
            self.snoop_socket.close()
            self.log.append("Socket closed\n")
            self.file.writelines(self.log)
            self.file.close()
            self.closed = True

import socket


class PrintTrace(SocketDuplexHook):

    def send_hook(self, data, **kwargs):
        print("Sent: {}".format(binascii.hexlify(data)))

    def recv_hook(self, data, **kwargs):
        print("Recv: {}".format(binascii.hexlify(data)))

    def recvfrom_hook(self, data, addr, **kwargs):
        print("Recv: {}".format(binascii.hexlify(data)))

    def sendto_hook(self, data, socket, **kwargs):
        print("Sent: {}".format(binascii.hexlify(data)))

    def send_exception(self, e):
        print("Exception: {}".format(e))


class ReplaySocket(PrintTrace):
    def __init__(self, snoop_socket, inject_socket, core, filename='/tmp/bt_hci.log'):
        SocketDuplexHook.__init__(self, snoop_socket, inject_socket, core)
        self.replace = True
        self.log = open(filename).readlines()
        self.index = 0
        if self.log[0].startswith("#"):
            self.index = 1

    def send_replace(self, data, **kwargs):
        encoded_data = ""  # type: str
        hex_data = binascii.hexlify(data)
        direction, encoded_data = self.log[self.index].split(" ", 1)
        if direction == "RX":
            # Some recieves aren't handled yet, wait a bit so the recv thread takes care of them.
            time.sleep(0.2)
            direction, encoded_data = self.log[self.index].split(" ", 1)
        assert (direction == "TX")
        log_data = binascii.unhexlify(encoded_data.rstrip('\n'))
        assert data == log_data, "Got {}, expected {}".format(hex_data, encoded_data)
        self.index += 1
        ty, data = self.log[self.index].split(" ", 1)
        if ty == "EX":
            self.index += 1
            raise socket.error(data)

    def recv_replace(self, length, **kwargs):
        time.sleep(0.001)
        direction, encoded_data = self.log[self.index].split(" ", 1)
        if direction == "RX":
            self.index += 1
            return binascii.unhexlify(encoded_data.rstrip('\n'))
        else:
            raise socket.timeout()

    def recvfrom_replace(self, length, **kwargs):
        time.sleep(0.001)
        direction, encoded_data = self.log[self.index].split(" ", 1)
        if direction == "RX":
            self.index += 1
            return binascii.unhexlify(encoded_data.rstrip('\n')), 1234
        else:
            raise socket.timeout()

    def getsockname(self):
        return (None, 0)


from internalblue.core import InternalBlue




def hook(core, socket_hook, **hookkwargs):
    # type: (Type[InternalBlue], Type[SocketDuplexHook], Any) -> None

    def wrap_socket_setup(orig_func):
        def wrapped_socket_setup(self, *args, **kwargs):
            if not self.replay:
                status = orig_func(self, *args, **kwargs)
            else:
                status = True
            h = socket_hook(self.s_snoop, self.s_inject, core=self, **hookkwargs)
            self.s_inject = h
            self.s_snoop = h
            return status

        return wrapped_socket_setup

    core._setupSockets = wrap_socket_setup(core._setupSockets)

    def wrap_teardown_sockets(orig_func):
        def wrapped_teardown_sockets(self, *args, **kwargs):
            if not self.replay:
                return orig_func(self, *args, **kwargs)
            else:
                self.s_inject.close()
                self.s_snoop.close()
        return wrapped_teardown_sockets

    core._teardownSockets = wrap_teardown_sockets(core._teardownSockets)


    def wrap_device_list(orig_func):
        def wrapped_device_list(self, *args, **kwargs):
            if not self.replay:
                return orig_func(self, *args, **kwargs)
            else:
                return [(self, "ReplayDevice", "ReplayDevice")]
        return wrapped_device_list



    core.device_list = wrap_device_list(core.device_list)
