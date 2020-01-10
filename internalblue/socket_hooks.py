import binascii
import time


class SocketRecvHook():
    def __init__(self, socket):
        # type: (socket.socket) -> None
        self.socket = socket
        self.replace = False

    def recv_hook(self, data):
        raise NotImplementedError()

    def recv_replace(self, length, **kwargs):
        raise NotImplementedError()

    def recv(self, length, **kwargs):
        if not self.replace:
            data = self.socket.recv(length, **kwargs)
        else:
            data = self.recv_replace(length, **kwargs)
        self.recv_hook(data)
        return data

    def recvfrom(self, length):
        # type: (int) -> Tuple[bytes, Any]
        if not self.replace:
            data, addr = self.socket.recvfrom(length)
            self.recv_hook(data)
            return data

class SocketInjectHook():
    def __init__(self, socket):
        # type: (socket.socket) -> None
        self.socket = socket
        self.replace = False

    def close(self):
        self.socket.close()

    def send(self,data):
        self.send_hook(data)
        if not self.replace:
            try:
                self.socket.send(data)
            except Exception as e:
                self.send_exception(e)
                raise e
        else:
            self.send_replace(data)

    def send_hook(self,result):
        raise NotImplementedError()

    def send_replace(self,data):
        raise NotImplementedError()

    def send_exception(self, e):
        raise NotImplementedError()


class SocketDuplexHook(SocketInjectHook, SocketRecvHook):

    def __init__(self, socket):
        # type: (socket.socket) -> None
        self.socket = socket
        self.replace = False
    pass



class HookBase():
    def send_hook(self,data):
        raise NotImplementedError
    def recv_hook(self, data):
        raise NotImplementedError


class TraceToFileHook(SocketDuplexHook):
    def __init__(self, socket, filename='/tmp/bt_hci.log'):
        SocketDuplexHook.__init__(self, socket)
        self.file = open(filename, 'a')
        self.replace = False
        self.log = []

    def recv_hook(self, data):
        line = "RX {}\n".format(binascii.hexlify(data))
        print(line)
        self.log.append(line)

    def send_hook(self, data):
        line = "TX {}\n".format(binascii.hexlify(data))
        print(line)
        self.log.append(line)

    def send_exception(self, e):
        line = "EX '{}'\n".format(e)
        print(line)
        self.log.append(line)

    def close(self):
        self.socket.close()
        self.log.append("Socket closed\n")
        self.file.writelines(self.log)
        self.file.close()


import socket


class PrintTrace(SocketDuplexHook):

    def send_hook(self, data, **kwargs):
        print("Sent: {}".format(binascii.hexlify(data)))

    def recv_hook(self, data, **kwargs):
        print("Recv: {}".format(binascii.hexlify(data)))

    def recvfrom_hook(self, data, **kwargs):
        print("Recv: {}".format(binascii.hexlify(data)))




class ReplaySocket():
    def __init__(self, filename='/tmp/bt.log'):
        super(ReplaySocket, self).__init__()
        self.log = open(filename).readlines()
        self.index = 0

    def send(self, data, **kwargs):
        encoded_data = "" # type: str
        direction, encoded_data = self.log[self.index].split(" ")
        assert(direction == "TX")
        log_data = binascii.unhexlify(encoded_data.rstrip('\n'))
        assert(data == log_data)
        self.index+=1

    def recv(self, **kwargs):
        time.sleep(0.01)
        direction, encoded_data = self.log[self.index].split(" ")
        if direction == "RX":
            return binascii.unhexlify(encoded_data.rstrip('\n'))
        else:
            raise socket.timeout()



from internalblue.core import InternalBlue

try:
    import typing
    from typing import Type
except ImportError:
    pass

def hook(core, socket_hook):
    # type: (Type[InternalBlue], Type[SocketDuplexHook]) -> None

    def wrap_socket_setup(orig_func):
        def wrapped_socket_setup(self, *args, **kwargs):
            status = orig_func(self, *args, **kwargs)
            if self.s_inject == self.s_snoop:
                h = socket_hook(self.s_inject)
                self.s_inject = h
                self.s_snoop = h
            else:
                self.s_inject = socket_hook(self.s_inject)
                self.s_snoop = socket_hook(self.s_snoop)
            return status

        return wrapped_socket_setup

    core._setupSockets = wrap_socket_setup(core._setupSockets)

