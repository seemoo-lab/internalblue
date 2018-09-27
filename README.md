InternalBlue
============

The firmware of the BCM4339 Bluetooth controller (Nexus 5) and its firmware
update mechanism have been reverse engineered. Based on that we developed a
Bluetooth experimentation framework which is able to patch the firmware and
therefore implement monitoring and injection tools for the lower layers of
the Bluetooth protocol stack.

The framework was presented at the MRMCD Conference 2018 in Darmstadt. The
talk was also recorded and includes an overview of the framework as well as
two demo usages at the end (Following a **Secure Simple Pairing procedure in
Wireshark** and implementing a **proof of concept for CVE-2018-5383**):

[![MRMCD 2018: InternalBlue](https://static.media.ccc.de/media/conferences/mrmcd/mrmcd18/154-hd_preview.jpg)](https://media.ccc.de/v/2018-154-internalblue-a-deep-dive-into-bluetooth-controller-firmware)
(Video-Link: https://media.ccc.de/v/2018-154-internalblue-a-deep-dive-into-bluetooth-controller-firmware)

Setup and Installation
----------------------

The framework uses ADB (Android Debug Bridge) to connect to the smartphone.
Either connect the phone via USB or setup ADB over TCP and make sure you
enable USB debugging in the developer settings of Android.

The Android device needs to run a Bluetooth stack that was compiled with
debugging features enabled. A detailed description on how to compile the
Bluetooth stack for your device can be found in the *README.md* file inside the
*android_bluetooth_stack* directory of this repository. It also contains
precompiled stacks for some devices. InternalBlue does not work without the
debug Bluetooth stack.

The InternalBlue framework is written in Python 2. You can install it together
with all dependencies by using the setup.py script:

    python2 setup.py install

It will install the following dependencies:
* pwntools

The pwntools module needs the binutils package for ARM 32-bit to be installed
on the system. This has to be installed manually by using the packet manager
of your Linux distribution:

    # for Arch Linux
    sudo pacman -S arm-none-eabi-binutils

    # for Ubuntu
    sudo apt install binutils-arm-linux-gnueabi


Usage
-----

The CLI (Command Line Interface) of InternalBlue can be started by running:

    python2 -m internalblue.cli

The setup.py installation will also place a shortcut to the CLI into the $PATH
so that it can be started from a command line using:

    internalblue

It should automatically connect to your Android phone through ADB.
Use the *help* command to display a list of available commands.

Requirements:
* recompiled bluetooth.default.so built with bdroid_CFLAGS='-DBT_NET_DEBUG=TRUE'
* Nexus 5 or Nexus 6P connected via ADB

Optional Requirements:
* LMP Wireshark Dissector Plugin (https://github.com/demantz/lmp_wireshark_dissector)



License
-------

Copyright 2018 Dennis Mantz

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
