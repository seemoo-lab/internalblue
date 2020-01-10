import binascii


class SocketRecvHook():
    def __init__(self, socket, recv_hook):
        self.recv_hook = recv_hook
        self.socket = socket

    def recv(self, length):
        data = self.socket.recv(length)
        self.recv_hook(data)
        return data


    def recvfrom(self, length):
        # type: (int) -> Tuple[bytes, Any]
        data, addr = self.socket.recvfrom(length)
        self.recv_hook(data)
        return data

class SocketInjectHook():
    def __init__(self, socket, send_hook):
        self.send_hook = send_hook
        self.socket = socket

    def close(self):
        self.socket.close()

    def send(self,data):
        self.send_hook(data)
        self.socket.send(data)





class SocketDuplexHook(SocketInjectHook, SocketRecvHook):

    def __init__(self, socket, send_hook, recv_hook):
        self.recv_hook = recv_hook
        self.send_hook = send_hook
        self.socket = socket
    pass

def wrap_socket_setup(orig_func, send_hook=None, recv_hook=None):
    def wrapped_socket_setup(self, *args, **kwargs):
        status = orig_func(self, *args, **kwargs)
        self.s_inject = SocketDuplexHook(self.s_inject, send_hook, recv_hook)
        self.s_snoop = SocketDuplexHook(self.s_snoop, send_hook, recv_hook)
        return status

    return wrapped_socket_setup

class HookBase():
    def send_hook(self,data):
        raise NotImplementedError
    def recv_hook(self, data):
        raise NotImplementedError


class TraceToFileHook(HookBase):
    def __init__(self,filename='/tmp/bt_hci.log'):
        self.file = open(filename, 'w')

    def recv_hook(self, data):
        line = "RX {}\n".format(binascii.hexlify(data))
        self.file.writelines([line])

    def send_hook(self, data):
        line = "TX {}\n".format(binascii.hexlify(data))
        self.file.writelines([line])


import socket


class PrintTrace(socket.socket):

    def send_hook(self, data):
        print("Sent: {}".format(binascii.hexlify(data)))

    def recv_hook(self, data):
        print("Recv: {}".format(binascii.hexlify(data)))



class ReplaySocket(socket.socket):
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

def hook(core, hook):
    # type: (Type[InternalBlue], HookBase) -> None
    core._setupSockets = wrap_socket_setup(core._setupSockets, hook.send_hook, hook.recv_hook)

