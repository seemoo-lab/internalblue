#!/usr/bin/env python2

# cli.py
#
# This file is meant to be executed by the user in order to start
# an interactive CLI. It creates an instance of the framework and
# enters a command loop which is implemented with the readline
# interface. Commands entered by the user are matched to the
# corresponding Cmd subclass in the cmds.py file and dispatched
# accordingly.
#
# Copyright (c) 2018 Dennis Mantz. (MIT License)
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

import core
import cmds

LOGFILE  = '_internalblue.log'
HISTFILE = "_internalblue.hist"

def print_banner():
    banner = """\
   ____     __                    _____  __
  /  _/__  / /____ _______  ___ _/ / _ )/ /_ _____
 _/ // _ \/ __/ -_) __/ _ \/ _ `/ / _  / / // / -_)
/___/_//_/\__/\__/_/ /_//_/\_,_/_/____/_/\_,_/\__/

by Dennis Mantz.

type <help> for usage information!\n\n"""
    for line in banner:
        term.output(text.blue(line))

def commandLoop(internalblue):
    while internalblue.running and not internalblue.exit_requested:
        cmd_instance = None
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
            cmd_instance = matching_cmd(cmdline, internalblue)

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
                internalblue.exit_requested = True
                break
        except Exception as e:
            internalblue.exit_requested = True      # Make sure all threads terminate
            log.critical("Uncaught exception (%s). Abort." % str(e))
            print(traceback.format_exc())
            break
        cmd_instance = None


# Main Program Start
def internalblue_cli():
    print_banner()
    internalblue = core.InternalBlue()

    # Restore readline history:
    if os.path.exists(HISTFILE):
        readline_history = read(HISTFILE)
        term.readline.history = readline_history.split('\n')

    # Readline Completions
    cmd_keywords = []
    for cmd in cmds.getCmdList():
        for keyword in cmd.keywords:
            cmd_keywords.append(keyword)
    readline_completer = term.completer.LongestPrefixCompleter(words=cmd_keywords)
    term.readline.set_completer(readline_completer)

    # setup sockets
    if not internalblue.connect():
        log.critical("No connection to target device.")
        exit(-1)

    # Enter command loop (runs until user quits)
    commandLoop(internalblue)

    # shutdown connection
    internalblue.shutdown()

    # Save readline history:
    f = open(HISTFILE, "w")
    f.write("\n".join(term.readline.history))
    f.close()

    # Cleanup
    log.info("Goodbye")


if __name__ == "__main__":
    internalblue_cli()

