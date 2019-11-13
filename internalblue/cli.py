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
import traceback
import argparse

from adbcore import ADBCore
from hcicore import HCICore
from sys import platform

import cmds

HISTFILE = "_internalblue.hist"

def print_banner():
    banner = """\
   ____     __                    _____  __
  /  _/__  / /____ _______  ___ _/ / _ )/ /_ _____
 _/ // _ \/ __/ -_) __/ _ \/ _ `/ / _  / / // / -_)
/___/_//_/\__/\__/_/ /_//_/\_,_/_/____/_/\_,_/\__/


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
            log.warn("commandLoop: ValueError: " + str(e))
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

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-directory", "-d", help="Set data directory. Default: ~/.internalblue")
    parser.add_argument("--verbose", "-v", help="Set log level to DEBUG", action="store_true")
    parser.add_argument("--ios-device", "-i", help="Tell internalblue to connect to a remote iPhone HCI socket. Specify socket IP address and port (i.e., 172.20.10.1:1234).")
    parser.add_argument("--serialsu", "-s", help="On ADB, directly try su/serial/busybox scripting, if you do not have a special bluetooth.default.so file.", action="store_true")
    parser.add_argument("--testdevice", "-t", help="Use a dummy test device to execute testcases", action="store_true")
    args = parser.parse_args()

    if args.data_directory is not None:
        data_directory = args.data_directory
    else:
        data_directory = os.path.expanduser("~") + "/.internalblue"
    if not os.path.exists(data_directory):
        os.mkdir(data_directory)

    if args.verbose:
        log_level = "debug"
    else:
        log_level = "info"

    # Readline Completions
    cmd_keywords = []
    for cmd in cmds.getCmdList():
        for keyword in cmd.keywords:
            cmd_keywords.append(keyword)
    readline_completer = term.completer.LongestPrefixCompleter(words=cmd_keywords)
    term.readline.set_completer(readline_completer)

    # Initalize cores and get devices
    # As macOS has additional dependencies (objc), only import it here if needed
    if args.ios_device:
        from ioscore import iOSCore
        connection_methods = [iOSCore(args.ios_device, log_level=log_level, data_directory=data_directory)]
    elif args.testdevice:
        from testcore import testCore
        connection_methods = [testCore(log_level=log_level, data_directory=data_directory)]
    elif platform == "darwin":
        from macoscore import macOSCore
        connection_methods = [
            macOSCore(log_level=log_level, data_directory=data_directory),
            ADBCore(log_level=log_level, data_directory=data_directory)]
    else:
        connection_methods = [
            ADBCore(log_level=log_level, data_directory=data_directory, serial=args.serialsu),
            HCICore(log_level=log_level, data_directory=data_directory)]

    devices = []
    for connection_method in connection_methods:
        devices.extend(connection_method.device_list())

    if len(devices) > 0:
        if len(devices) == 1:
            device = devices[0]
        else:
            i = options('Please specify device:',  [d[2] for d in devices], 0)
            device = devices[i]

        # Setup device
        reference = device[0]
        reference.interface = device[1]

        # Restore readline history:
        if os.path.exists(reference.data_directory + "/" + HISTFILE):
            readline_history = read(reference.data_directory + "/" + HISTFILE)
            term.readline.history = readline_history.split('\n')

        # Connect to device
        if not reference.connect():
            log.critical("No connection to target device.")
            exit(-1)

        # Enter command loop (runs until user quits)
        commandLoop(reference)

        # shutdown connection
        reference.shutdown()

        # Save readline history:
        f = open(reference.data_directory + "/" + HISTFILE, "w")
        f.write("\n".join(term.readline.history))
        f.close()

    # Cleanup
    log.info("Goodbye")


if __name__ == "__main__":
    internalblue_cli()

