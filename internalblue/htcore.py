#!/usr/bin/env python2

from multiprocessing import Process, Queue
from os import popen
from Queue import Empty as QueueEmpty
import re
from time import sleep

from pwn import *

from core import InternalBlue
from hci import HCI_Cmd, HCI_Event
#from htresponse import HTResponse


class HTCore(InternalBlue):

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='info', fix_binutils='True', data_directory="."):
        super(HTCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils, data_directory=".")
        self.hcitool = 'sudo hcitool'

        # wait a few seconds after reattach after crash to check if the device reappeared
        self.sanitycheckonreboot = False
        self.sanitychecksleep = 8

    def device_list(self):
        """
        Return a list of connected hci devices
        """

        # higher timeout here to allow the user to enter sudo password initally
        # (should be cached by sudo afterwards)
        log.info("Running hcitool with sudo...")
        response = self._run(self.hcitool + ' dev', timeout=20).split() 

        device_list = []
        # checks if a hci device is connected
        if len(response) > 1 and len(response) % 2 == 1:
            response = response[1:]
            for interface, address in zip(response[0::2], response[1::2]):
                device_list.append([self, interface, 'hci: %s (%s)' % (address, interface)])

        if len(device_list) == 0:
            log.info('No connected HCI device found')
            return []
        elif len(device_list) == 1:
            log.info('Found one HCI device, %s' % device_list[0][2])
        else:
            log.info('Found multiple HCI devices')

        return device_list

    def local_connect(self):
        """
        So far no special actions to run Wireshark...
        TODO This means currently only callbacks for specific hcitool commands
             started via InternalBlue - open wireshark directly on the host machine!
        """

        if not self.interface:
            log.warn("No HCI identifier is set")
            return False

        return True

    def _run_async(self, cmd, queue):
        """
        Is called by _run_command and prevents the program not to hang if the bluetooth controller has crashed
        """

        log.debug('Run cmd: %s' % cmd)
        queue.put(popen(cmd).read()) #TODO should be closed

    def _process(self, cmd, queue):
        p = Process(target=self._run_async, args=(cmd, queue,))
        p.start()
        return p

    def _run(self, cmd, timeout=1): 
        """
        Runs provided cmd
        """

        # define output queue where hcitool response is passed
        queue = Queue()

        # define and start process
        process = self._process(cmd, queue)

        # check if process hangs (wait 1 second)
        try:
            log.debug('hcitool cmd: %s', cmd)
            response = queue.get(True, timeout)
            process.join()

            log.debug('hcitool response: \n%s' % response)

            return response

        except QueueEmpty:
            return None
        
            # FIXME on Raspi this actually kills the hci0 device :(
            # failed because bluetooth chip crashed
            log.warning('HCI device crashed from cmd: %s', cmd)
            log.info('Reattach device, this will take a few seconds')

            # how many devices? n = devices * 2 + 1
            if self.sanitycheckonreboot:
                n = len(self._run(self.hcitool + ' dev').split())

            # need to wait a few seconds otherwise command fails
            self._process('sleep 5 && sudo systemctl restart hciuart.service', queue)

            # blocks between 5 and 10 seconds
            queue.get(True)

            if self.sanitycheckonreboot:
                log.info('Check if the device has been reattached, this will take some seoncds')

                sleep(self.sanitychecksleep)

                # check if device is rebooted
                if len(self._run(self.hcitool + ' dev').split()) != n:
                    log.critical('Could not reboot Bluetooth chip, terminating InternalBlue!')

                    exit(-1)

                log.info('device is reattached')

        return None

    def sendHciCommand(self, opcode, data, timeout=2):
        """
        Send an arbitrary HCI packet
        """
        
        #sleep(0.5) # required by commands like dumpmem since we don't wait for callback of previous command

        log.debug("sendHciCommand: opcode %x" % opcode)
        
        # split opcode into first and second byte
        #ogf, ocf = divmod(opcode, 0x100)
        ogf = (opcode & 0xff00) >> 10 # HCI_GRP_LINK_CONTROL_CMDS (0x01 << 10) /* 0x0400 */ etc.
        ocf = opcode & 0x00ff
        
        log.debug("sendHciCommand: ogf %x ocf %x" % (ogf, ocf))
        

        # convert back to hex
        ogf = hex(ogf)
        ocf = hex(ocf)

        data = ' '.join(['0x' + hex(ord(data[i]))[2:].zfill(2) for i in range(len(data))])

        # finalize cmd
        cmd = self.hcitool + ' -i %s cmd %s %s %s' % (self.interface, ogf, ocf, data)

        response = self._run(cmd, timeout)

        if not response or not HTResponse.is_valid(response):
            # something went wrong
            log.critical('Command failed: %s' % cmd)
            return False

        # otherwise return response packet
        event_payload = HTResponse(response).event.data

        return event_payload
    
    def sendH4(self, h4type, data, timeout=2):
        """
        Currently not supported via hcitool, need to dig deeper into bluez...
        """
        
        log.warn("Sending raw H4 UART is currently not supported with hcitool.")
        
        return False

class HTResponse(object):

    hex_pattern = re.compile(r'(0x[0-9a-fA-F]*)')
    plen_pattern = re.compile(r'plen (\d*)')
    payload_pattern = re.compile(r'(?<=\s)[0-9a-fA-F]{2}(?![0-9a-fA-F])')

    @staticmethod
    def is_valid(response):
        """
        Checks if the provided input is a valid hci response
        :param response: response from hcitool cmd ... as string
        :return: boolean
        """

        # convert to lower case
        response = response.lower()

        if response.find('< hci command:') == -1 or response.find('> hci event:') == -1:
            return False

        return True

    def __str__(self):
        return "%s\n%s" % (self.cmd, self.event)

    def __init__(self, ht_response):
        """
        Creates a hcitool response
        :param ht_response: valid response from hcitool cmd ... as string
        """

        self.ht_response = ht_response

        # remove lower case
        ht_response = ht_response.lower()

        ogf, ocf, event_code = re.findall(HTResponse.hex_pattern, ht_response)

        cmd_plen, event_plen = re.findall(HTResponse.plen_pattern, ht_response)
        cmd_plen = int(cmd_plen)
        event_plen = int(event_plen)

        separator = ht_response.find('>')

        command = ' '.join(ht_response[0:separator].split('\n')[1:])
        event = ' '.join(ht_response[separator:].split('\n')[1:])

        cmd_payload = ''.join(re.findall(HTResponse.payload_pattern, command)).decode('hex')
        event_payload = ''.join(re.findall(HTResponse.payload_pattern, event)).decode('hex')

        self.cmd = HCI_Cmd((int(ogf, 0) << 10) | int(ocf, 0), cmd_plen, cmd_payload)
        self.event = HCI_Event(int(event_code, 0), event_plen, event_payload)

        log.debug(self)

        # if plen and payload do not match there might be sth wrong...
        if cmd_plen != len(cmd_payload) or event_plen != len(event_payload):
            log.warn('HCI Command plen %s (%s) or HCI Event plen %s (%s) does not match: \n%s' % (cmd_plen, len(cmd_payload), event_plen, len(event_payload), self))
        
