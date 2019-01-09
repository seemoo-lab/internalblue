#!/usr/bin/env python2

from multiprocessing import Process, Queue
from os import popen
from Queue import Empty as QueueEmpty
from time import sleep

from pwn import *

from core import InternalBlue
from hci import HCI_Cmd
from htresponse import HTResponse


class HTCore(InternalBlue):

    def __init__(self, queue_size=1000, btsnooplog_filename='btsnoop.log', log_level='debug', fix_binutils='True'):
        super(HTCore, self).__init__(queue_size, btsnooplog_filename, log_level, fix_binutils)

        # shift ogf 2 bits to the right
        HCI_Cmd.HCI_CMD_STR = {(((divmod(k, 0x100)[0] >> 2) % pow(2, 8)) << 8) + divmod(k, 0x100)[1]: v for k, v in HCI_Cmd.HCI_CMD_STR.iteritems()}
        HCI_Cmd.HCI_CMD_STR_REVERSE = {v: k for k, v in HCI_Cmd.HCI_CMD_STR.iteritems()}

        # get vsc commands from hci class
        self.init_vsc_variables()

        # wait a few seconds after reattach after crash to check if the device reappeared
        self.sanitycheckonreboot = False
        self.sanitychecksleep = 8

    def device_list(self):
        """
        Return a list of connected hci devices
        """

        response = self._run('hcitool dev').split()

        device_list = []
        # checks if a hci device is connected
        if len(response) > 1 and len(response) % 2 == 1:
            response = response[1:]
            for interface, address in zip(response[0::2], response[1::2]):
                device_list.append([self, interface, 'hci: %s (%s)' % (address, interface)])

        if len(device_list) == 0:
            log.info('No connected hci device found')
            return []
        elif len(device_list) == 1:
            log.info('Found 1 hci devic, %s' % device_list[0][2])
        else:
            log.info('Found multiple hci devices')

        return device_list

    def local_connect(self):
        """
        Start the framework by connecting to the Bluetooth Stack of the Android
        device via adb and the debugging TCP ports.
        """

        if not self.interface:
            log.warn("No hci identifier is set")
            return False

        # Import fw depending on device
        global fw    # put the imported fw into global namespace
        import fw_rpi3 as fw

        self.fw = fw    # Other scripts (such as cmds.py) can use fw through a member variable

        return True

    def _run_async(self, cmd, queue):
        """
        Is called by _run_command and prevents the program not to hang if the bluetooth controller has crashed
        """

        log.debug('Run cmd: %s' % cmd)
        queue.put(popen(cmd).read())

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
            response = queue.get(True, 1)
            process.join()

            log.debug('Cmd: %s, response: \n%s' % (cmd, response))

            return response

        except QueueEmpty:
            # failed because bluetooth chip crashed
            log.warning('Hci device crashed from cmd: %s', cmd)
            log.info('Reattach device, this will take a few seconds')

            # how many devices? n = devices * 2 + 1
            if self.sanitycheckonreboot:
                n = len(self._run('hcitool dev').split())

            # need to wait a few seconds otherwise command fails
            self._process('sleep 5 && sudo systemctl restart hciuart.service', queue)

            # blocks between 5 and 10 seconds
            queue.get(True)

            if self.sanitycheckonreboot:
                log.info('Check if the device has been reattached, this will take some seoncds')

                sleep(self.sanitychecksleep)

                # check if device is rebooted
                if len(self._run('hcitool dev').split()) != n:
                    log.critical('Could not reboot bluetooth chip, terminating internalblue')

                    exit(-1)

                log.info('device is reattached')

        return False

    def sendHciCommand(self, opcode, data, timeout=1):
        """
        Send an arbitrary HCI packet
        """

        # split opcode into first and second byte
        ogf, ocf = divmod(opcode, 0x100)

        # convert back to hex
        ogf = hex(ogf)
        ocf = hex(ocf)

        data = ' '.join(['0x' + hex(ord(data[i]))[2:].zfill(2) for i in range(len(data))])

        # finalize cmd
        cmd = 'hcitool -i %s cmd %s %s %s' % (self.interface, ogf, ocf, data)

        response = self._run(cmd, timeout)

        if not response or not HTResponse.is_valid(response):
            # something went wrong
            log.critical('Command failed: %s' % cmd)
            return False

        # otherwise return response packet
        event_payload = HTResponse(response).event.payload

        log.info('%s, payload: %s' % (cmd, event_payload))

        return event_payload
