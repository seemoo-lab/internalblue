#!/usr/bin/env python2

import socket
import Queue
import hci

from pwn import *

from core import InternalBlue
import binascii

class testCore(InternalBlue):
    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(testCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")
        file = open('memdump.bin', mode='rb')
        self.memory = file.read()
        file.close()
        self.doublecheck = False

    def device_list(self):
        """
        Get a list of connected devices
        """

        if self.exit_requested:
            self.shutdown()

        if self.running:
            log.warn("Already running. Call shutdown() first!")
            return []

        # assume that a explicitly specified iPhone exists
        device_list = [(self, "Testchip", "Testchip")]

        return device_list

    def sendH4(self, h4type, data, timeout=2):
        """
        Send an arbitrary HCI packet by pushing a send-task into the
        sendQueue. This function blocks until the response is received
        or the timeout expires. The return value is the Payload of the
        HCI Command Complete Event which was received in response to
        the command or None if no response was received within the timeout.
        """

        queue = Queue.Queue(1)

        try:
            self.sendQueue.put((h4type, data, queue, None), timeout=timeout)
            ret = queue.get(timeout=timeout)
            return ret
        except Queue.Empty:
            log.warn("sendH4: waiting for response timed out!")
            return None
        except Queue.Full:
            log.warn("sendH4: send queue is full!")
            return None

    def local_connect(self):
        return True

    def _setupSockets(self):
        self.hciport = random.randint(60000, 65535 - 1)
        log.debug("_setupSockets: Selected random ports snoop=%d and inject=%d" % (self.hciport, self.hciport + 1))
        log.info("Wireshark configuration (on Loopback interface): udp.port == %d || udp.port == %d" % (
        self.hciport, self.hciport + 1))

        # Create s_snoop socket
        self.s_snoop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_snoop.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s_snoop.bind(('127.0.0.1', self.hciport))
        self.s_snoop.settimeout(0.5)
        self.s_snoop.setblocking(True)

        # Create s_inject
        self.s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_inject.settimeout(0.5)
        self.s_inject.setblocking(True)

        time.sleep(1.5)

        return True

    def _recvThreadFunc(self):
        '''
        log.debug("Receive Thread started.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # read record data
            try:
                data, addr = self.s_snoop.recvfrom(1024)
                record_data = data
            except socket.timeout:
                continue # this is ok. just try again without error

            if not self.exit_requested:
                # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
                record = (hci.parse_hci_packet(record_data), 0, 0, 0, 0, 0) #TODO not sure if this causes trouble?
                log.debug("Recv: " + str(record[0]))

                # Put the record into all queues of registeredHciRecvQueues if their
                # filter function matches.
                for queue, filter_function in self.registeredHciRecvQueues: # TODO filter_function not working with bluez modifications
                    try:
                        queue.put(record, block=False)
                    except Queue.Full:
                        log.warn("recvThreadFunc: A recv queue is full. dropping packets..>" + record_data)

                # Call all callback functions inside registeredHciCallbacks and pass the
                # record as argument.
                for callback in self.registeredHciCallbacks:
                    callback(record)
        '''

        log.debug("Receive Thread terminated.")

    def _sendThreadFunc(self):
        log.debug("Send Thread started.")
        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # Wait for 'send task' in send queue
            try:
                task = self.sendQueue.get(timeout=0.5)
            except Queue.Empty:
                continue

            # Extract the components of the task
            h4type, data, queue, filter_function = task

            # Prepend UART TYPE and length.
            out = p8(h4type) + p8(len(data)) + data

            # Send command to the chip using IOBluetoothExtended framework
            h4type, data, queue, filter_function = task
            opcode = binascii.hexlify(data[1]) + binascii.hexlify(data[0])
            log.debug("Sending command: 0x" + binascii.hexlify(data))

            # if the caller expects a response: register a queue to receive the response
            if queue is not None and filter_function is not None:
                recvQueue = Queue.Queue(1)
                self.registerHciRecvQueue(recvQueue, filter_function)

            # if the caller expects a response:
            # Wait for the HCI event response by polling the recvQueue

            if queue is not None and filter_function is not None:
                # Return responses according to the opcode & operands
                if opcode == '1001':
                    record_data = '040E0C0101100006b415060f000e22'.decode('hex')
                    data = hci.parse_hci_packet(record_data).data
                elif opcode == 'fc4d':
                    #time.sleep(0.5)
                    length = int(binascii.hexlify(data[7]), 16)
                    address = int(binascii.hexlify(data[6]+data[5]+data[4]+data[3]), 16)
                    log.info('data: ' + str(''.join('{:02x}'.format(ord(c)) for c in data)) + ', address: ' + str(hex(address)))
                    data = '014dfc00'.decode('hex') + self.memory[address:address+length]
                    #log.debug(''.join('{:02x}'.format(ord(c)) for c in data))
                else:
                    print(opcode)

                queue.put(data)
                self.unregisterHciRecvQueue(recvQueue)

        log.debug("Send Thread terminated.")

    def enableBroadcomDiagnosticLogging(self, enable):
        return

    def _teardownSockets(self):
        return True

    def shutdown(self):
        return True