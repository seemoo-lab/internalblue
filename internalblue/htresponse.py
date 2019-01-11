#!/usr/bin/env python2

import re

from pwn import *

from hci import HCI_Cmd, HCI_Event


class HciCmd(object):

    def __str__(self):
        return "hci command: %s\n" \
               "\topcode: %s (ogf: %s, ocf: %s)\n" \
               "\tplen: %s\n" \
               "\tpayload: %s" \
               % (self.name, self.opcode, self.ogf, self.ocf, self.payload_length, self.payload)

    def __init__(self, ogf, ocf, payload_length, payload):
        self.ogf = ogf
        self.ocf = ocf
        self.payload_length = payload_length
        self.payload = payload

        self.opcode = '0x' + hex((int(ogf, 16) << 8) + int(ocf, 16))[2:].zfill(4)
        self.name = HCI_Cmd.cmd_name(self.opcode)


class HciEvent(object):

    def __str__(self):
        return "hci event: %s\n" \
               "\tcode: %s\n" \
               "\tplen: %s\n" \
               "\tpayload: %s" \
               % (self.name, self.code, self.payload_length, self.payload)

    def __init__(self, code, payload_length, payload):
        self.code = code
        self.payload_length = payload_length
        self.payload = payload

        self.name = HCI_Event.event_name(self.code)


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

        cmd_payload = ''.join(re.findall(HTResponse.payload_pattern, command))
        event_payload = ''.join(re.findall(HTResponse.payload_pattern, event))

        self.cmd = HciCmd(
            ogf,
            ocf,
            cmd_plen,
            cmd_payload
        )

        self.event = HciEvent(
            event_code,
            event_plen,
            event_payload
        )

        log.debug(self)

        # if plen and payload does not match log and exit
        # cmd_plen and event_plen are in byte, cmd_payload, event_payload in nibble
        if cmd_plen*2 != len(cmd_payload) or event_plen*2 != len(event_payload):
            log.critical('HCI Command plen %s (%s) or HCI Event plen %s (%s) does not match: \n%s' % (cmd_plen, len(cmd_payload), event_plen, len(event_payload), self))
            exit(-1)


