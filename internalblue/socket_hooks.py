






class SocketRecvHook():
    def __init__(self, socket, recv_hook):
        self.recv_hook = recv_hook
        self.socket = socket

    def recv(self, length):
        data = self.socket.recv(length)
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



import binascii
def send_print_hook(data):
    print("Sent: ", binascii.hexlify(data))

def recv_print_hook(data):
    print("Recv: ", binascii.hexlify(data))

class SocketDuplexHook(SocketInjectHook, SocketRecvHook):

    def __init__(self, socket, send_hook=send_print_hook, recv_hook=recv_print_hook):
        self.recv_hook = recv_hook
        self.send_hook = send_hook
        self.socket = socket
    pass

def wrap_socket_setup(orig_func, send_hook=None, recv_hook=None):
    def wrapped_socket_setup(self, *args, **kwargs):
        status = orig_func(self, *args, **kwargs)
        self.s_inject = SocketDuplexHook(self.s_inject)
        self.s_snoop = SocketDuplexHook(self.s_snoop)
        return status

    return wrapped_socket_setup