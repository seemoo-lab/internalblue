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
import os
import signal
import time
import traceback

import brcm_bt.brcm_bt
import cmds


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

def commandLoop():
    while brcmbt.running and not brcmbt.exit_requested:
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
            cmd_instance = matching_cmd(cmdline, brcmbt)

            # Empty queue:
            while brcmbt.recvPacket(timeout=0.1) != None:
                pass

            if(not cmd_instance.work()):
                log.warn("Command failed: " + str(cmd_instance))
        except ValueError as e:
            log.warn(str(e))
            continue
        except KeyboardInterrupt:
            if(cmd_instance != None):
                cmd_instance.abort_cmd()
            else:
                log.info("Got Ctrl-C; exiting...")
                brcmbt.exit_requested = True
                break
        except Exception as e:
            brcmbt.exit_requested = True      # Make sure all threads terminate
            log.critical("Uncaught exception (%s). Abort." % str(e))
            print(traceback.format_exc())
            break
        cmd_instance = None
            


#
# Main Program Start
#

print_banner()

# settings
context.log_level = 'info'
context.log_file = '_brcm_bt_debugtool.log'
context.arch = "thumb"

brcmbt = brcm_bt.brcm_bt.BrcmBt()

# Restore readline history:
if os.path.exists("_brcm_bt_debugtool.hist"):
    readline_history = read("_brcm_bt_debugtool.hist")
    term.readline.history = readline_history.split('\n')

# Readline Completions
cmd_keywords = []
for cmd in cmds.getCmdList():
    for keyword in cmd.keywords:
        cmd_keywords.append(keyword)
readline_completer = term.completer.LongestPrefixCompleter(words=cmd_keywords)
term.readline.set_completer(readline_completer)

# setup sockets
if not brcmbt.connect():
    log.critical("No connection to target device.")
    exit(-1)

# Enter command loop (runs until user quits)
commandLoop()

# shutdown connection
brcmbt.shutdown()

# Save readline history:
f = open("_brcm_bt_debugtool.hist", "w")
f.write("\n".join(term.readline.history))
f.close()

# Cleanup
log.info("Goodbye")

