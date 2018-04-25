#!/usr/bin/python2

# brcm_bt_debugtool.py
#
# This is a helper tool for debuging and reversing Broadcom Bluetooth chips.
# It requires a smartphone with compatible BCM chip and patched bluetooth stack
# which is connected via adb. Also pwntools must be installed.
# Features include dumping and manipulating memory in various ways.
#
# The tool is modular and allows adding new commands in a simple way (see cmds.py)
# HCI code was partially taken from https://github.com/joekickass/python-btsnoop
#
# Copyright (c) 2017 Dennis Mantz. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.


from pwn import *
import socket
import sys
import os
import signal
import time
import datetime
import Queue
import traceback
from glob import glob

import global_state
import hci
import cmds


# Globals
s_inject = None
s_snoop = None
hci_tx = None
write_btsnooplog = True
btsnooplog_file = None
recvQueue = Queue.Queue()
recvThread = None

def print_banner():
    banner = """\
   ___                     ___ ______    ___      __             __            __
  / _ )__________ _       / _ )_  __/   / _ \___ / /  __ _____ _/ /____  ___  / /
 / _  / __/ __/  ' \     / _  |/ /     / // / -_) _ \/ // / _ `/ __/ _ \/ _ \/ /
/____/_/  \__/_/_/_/    /____//_/     /____/\__/_.__/\_,_/\_, /\__/\___/\___/_/
                                                         /___/
by Dennis Mantz.

type <help> for usage information!\n\n"""
    for line in banner:
        term.output(text.yellow(line))

def check_binutils():
    # Test if arm binutils is in path so that asm and disasm work:
    saved_loglevel = context.log_level
    context.log_level = 'critical'
    try:
        pwnlib.asm.which_binutils('as')
        context.log_level = saved_loglevel
        return True
    except PwnlibException:
        context.log_level = saved_loglevel
        log.debug("pwnlib.asm.which_binutils() cannot find 'as'!")

    # Work around for arch (with installed arm-none-eabi-binutils)
    def which_binutils_fixed(tool):
        pattern = "arm-*-%s" % tool
        for directory in os.environ['PATH'].split(':'):
            res = sorted(glob(os.path.join(directory, pattern)))
            if res:
                return res[0]
        raise PwnlibException("Could not find tool %s." % tool)

    try:
        which_binutils_fixed('as')
        # yeay it worked! fix it in pwnlib:
        pwnlib.asm.which_binutils = which_binutils_fixed
        log.debug("installing workaround for pwnlib.asm.which_binutils() ...")
        return True
    except PwnlibException:
        log.warn("pwntools cannot find binutils for arm architecture. Disassembing will not work!")
        return False

def read_btsnoop_hdr():
    data = s_snoop.recv(16)
    if(len(data) < 16):
        return None
    if(write_btsnooplog):
        btsnooplog_file.write(data)

    btsnoop_hdr = (data[:8], u32(data[8:12]),u32(data[12:16]))
    log.debug("BT Snoop Header: %s, version: %d, data link type: %d" % btsnoop_hdr)
    return btsnoop_hdr

def parse_time(time):
    """
    Record time is a 64-bit signed integer representing the time of packet arrival,
    in microseconds since midnight, January 1st, 0 AD nominal Gregorian.

    In order to avoid leap-day ambiguity in calculations, note that an equivalent
    epoch may be used of midnight, January 1st 2000 AD, which is represented in
    this field as 0x00E03AB44A676000.
    """
    time_betw_0_and_2000_ad = int("0x00E03AB44A676000", 16)
    time_since_2000_epoch = datetime.timedelta(microseconds=time) - datetime.timedelta(microseconds=time_betw_0_and_2000_ad)
    return datetime.datetime(2000, 1, 1) + time_since_2000_epoch

def recvThreadFunc():
    log.debug("Receive Thread started.")

    stackDumpReceiver = hci.StackDumpReceiver()

    while not global_state.exit_requested:
        # Little bit ugly: need to re-apply changes to the global context to the thread-copy
        context.log_level = global_state.log_level

        record_hdr = b''
        while(not global_state.exit_requested and len(record_hdr) < 24):
            try:
                recv_data = s_snoop.recv(24 - len(record_hdr))
                if len(recv_data) == 0:
                    log.info("bt_snoop socket was closed by remote site. sending Ctrl-C...")
                    global_state.exit_requested = True
                    os.kill(os.getpid(), signal.SIGINT)
                    break
                record_hdr += recv_data
            except socket.timeout:
                pass # this is ok. just try again without error

        if not record_hdr or len(record_hdr) != 24:
            if not global_state.exit_requested:
                log.error("Cannot recv record_hdr")
                global_state.exit_requested = True
            break

        if(write_btsnooplog):
            btsnooplog_file.write(record_hdr)

        orig_len, inc_len, flags, drops, time64 = struct.unpack( ">IIIIq", record_hdr)

        record_data = b''
        while(not global_state.exit_requested and len(record_data) < inc_len):
            try:
                recv_data = s_snoop.recv(inc_len - len(record_data))
                if len(recv_data) == 0:
                    log.info("bt_snoop socket was closed by remote site. sending Ctrl-C...")
                    global_state.exit_requested = True
                    os.kill(os.getpid(), signal.SIGINT)
                    break
                record_data += recv_data
            except socket.timeout:
                pass # this is ok. just try again without error
        
        if(write_btsnooplog):
            btsnooplog_file.write(record_data)

        try:
            parsed_time = parse_time(time64)
        except OverflowError:
            parsed_time = None

        record = (hci.parse_hci_packet(record_data), orig_len, inc_len, flags, drops, parsed_time)

        log.debug("Recv: [" + str(parsed_time) + "] " + str(record[0]))

        if(record != None and global_state.cmd_running):
            recvQueue.put(record)

        stackDumpReceiver.recvPacket(record[0])

    log.debug("Receive Thread terminated.")



def setupSockets():
    global s_snoop, s_inject

    saved_loglevel = context.log_level
    context.log_level = 'warn'
    try:
        adb.forward(8872)
        adb.forward(8873)
    except PwnlibException as e:
        log.warn("Setup adb port forwarding failed: " + str(e))
        return False
    finally:
        context.log_level = saved_loglevel
    
    # Connect to hci injection port
    s_inject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_inject.connect(('127.0.0.1', 8873))
    s_inject.settimeout(0.5)

    # Connect to hci snoop log port
    s_snoop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_snoop.connect(('127.0.0.1', 8872))
    s_snoop.settimeout(0.5)

    # Read btsnoop header
    if(read_btsnoop_hdr() == None):
        log.warn("Could not read btsnoop header")
        s_inject.close()
        s_snoop.close()
        s_inject = s_snoop = None
        return False
    return True

def teardownSockets():
    global s_inject, s_snoop

    if(s_inject != None):
        s_inject.close()
        s_inject = None
    if(s_snoop != None):
        s_snoop.close()
        s_snoop = None

def commandLoop():
    while(not global_state.exit_requested):
        try:
            cmdline = term.readline.readline(prompt='> ').strip()
            cmdword = cmdline.split(' ')[0].split('=')[0]
            if(cmdword == ''):
                continue
            log.debug("Command Line: [[" + cmdword + "]] " + cmdline)
            matching_cmd = cmds.findCmd(cmdword)
            if matching_cmd == None:
                log.warn("Command unknown: " + cmdline)
                continue
            cmd_instance = matching_cmd(cmdline, recvQueue, hci_tx)
            global_state.cmd_running = True

            # Empty queue:
            while True:
                try:
                    recvQueue.get_nowait()
                except Queue.Empty:
                    break

            if(not cmd_instance.work()):
                log.warn("Command failed: " + str(cmd_instance))
        except ValueError as e:
            log.warn(str(e))
            continue
        except KeyboardInterrupt:
            if(global_state.cmd_running):
                cmd_instance.abort_cmd()
            else:
                log.info("Got Ctrl-C; exiting...")
                global_state.exit_requested = True
                break
        except Exception as e:
            global_state.exit_requested = True      # Make sure all threads terminate
            log.critical("Uncaught exception (%s). Abort." % str(e))
            print(traceback.format_exc())
            break
        global_state.cmd_running = False
            


#
# Main Program Start
#

print_banner()

# settings
context.log_level = 'info'
context.log_file = '_brcm_bt_debugtool.log'
context.arch = "thumb"

check_binutils()

# Restore readline history:
if os.path.exists("_brcm_bt_debugtool.hist"):
    readline_history = read("_brcm_bt_debugtool.hist")
    term.readline.history = readline_history.split('\n')

if(write_btsnooplog):
    btsnooplog_file = open('btsnoop.log','wb', 0)  # Write unbuffered!

# Readline Completions
cmd_keywords = []
for cmd in cmds.getCmdList():
    for keyword in cmd.keywords:
        cmd_keywords.append(keyword)
readline_completer = term.completer.LongestPrefixCompleter(words=cmd_keywords)
term.readline.set_completer(readline_completer)

# Check for connected adb devices
adb_devices = adb.devices()
if(len(adb_devices) == 0):
    log.critical("No adb devices found.")
    exit(-1)
if(len(adb_devices) > 1):
    log.info("Found multiple adb devices. ")
    choice = options("Please choose:", [d.serial + ' (' + d.model + ')' for d in adb_devices])
    context.device = adb_devices[choice].serial
else:
    log.info("Using adb device: %s (%s)" % (adb_devices[0].serial, adb_devices[0].model))
    context.device = adb_devices[0].serial

# setup sockets
if not setupSockets():
    log.critical("No connection to target device.")
    exit(-1)

# start receive thread
recvThread = context.Thread(target=recvThreadFunc)
recvThread.start()

hci_tx = hci.HCI_TX(s_inject)

# Enter command loop (runs until user quits)
commandLoop()

# Save readline history:
f = open("_brcm_bt_debugtool.hist", "w")
f.write("\n".join(term.readline.history))
f.close()

# Cleanup
recvThread.join()
teardownSockets()
if(write_btsnooplog):
    btsnooplog_file.close()
log.info("Goodbye")

