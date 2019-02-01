Firmware Versions
=================

This package adds support for different Broadcom and Cypress firmware versions.
A list of known versions can be found below, however we only have firmware information on a subset of these.
Results are based on real world testing, this list is very incomplete. If you know more versions, input is appreciated.



Vendor | Version | SubVersion | Firmware    | Devices 
-------| ------- | ---------- | ----------- | -------
0x000f |    0x04 |     0x4217 | BCM4329B1   | iPhone 4
0x000f |    0x04 |     0x21d0 |             | iMac 27" late 2009 
0x000f |    0x04 |     0x422a | BCM4331     | MacBook Pro early 2011
0x000f |    0x05 |     0x4203 | BCM2034B    | Thinkpad T420
0x000f |    0x06 |     0x229b | BCM20702A3  | MacBook Pro 13" mid 2012 (A1278)
0x000f |    0x06 |     0x4103 | BCM4330B1   | iPhone 4s
0x000f |    0x07 |     0x220f | BCM20736S   | Equiva Radiator Thermostat CC-RT-BLE-EQ
0x000f |    0x07 |     0x2203 | BCM43342    | iPhone 5s
0x000f |    0x07 |     0x2209 | BCM43430A1  | Raspberry Pi 3
0x000f |    0x07 |     0x230f | BCM4356A2   | Xperia Z5
0x000f |    0x07 |     0x410d |             | iPhone 5 (A1429)
0x000f |    0x07 |     0x6109 | BCM4335C0   | Nexus 5, Xperia Z3 Compact, Samsung Galaxy Note 3
0x000f |    0x08 |     0x6119 | BCM4345C0   | Raspberry Pi 3+, Honor 8
0x000f |    0x08 |     0x21a1 |             | MacBook Pro Retina 13" early 2015 
0x000f |    0x08 |     0x21a6 |             | MacBook Pro early 2015
0x000f |    0x08 |     0x2248 |             | MacBook Pro 2016
0x000f |    0x08 |     0x240f | BCM4358A3   | Nexus 6P, Samsung Galaxy S6, Samsung Galaxy S6 edge
0x000f |    0x08 |     0x4109 | BCM4345     | iPhone 6
0x000f |    0x08 |     0x430a |             | iPad Pro (MLMW2FD/A)
0x000f |    0x08 |     0x6103 |             | iPhone 7 (A1778)
0x000f |    0x08 |     0x6106 |             | Samsung Galaxy S7
0x000f |    0x08 |     0x6206 |             | iPhone SE
0x000f |    0x09 |     0x2040 |             | Apple Watch Series 3
0x000f |    0x09 |     0x411a |             | Samsung Galaxy S8
0x0131 |    0x09 |     0x4208 | CYW20735B1  | BLE/BR Bluetooth 5.0 Evaluation Kit


[Bluetooth versions](https://www.bluetooth.com/specifications/assigned-numbers/link-manager) 

[Company identifiers](https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers)


Firmware Related Setup
----------------------
The following steps are required to use the CYW20735B1 evaluation kit as normal HCI device on Linux with Bluez.
 

**1. Setup as HCI device**

You need to set the baud rate to 3 Mbit/s. Replace `/dev/ttyUSB0` with your device.

    btattach -B /dev/ttyUSB0 -S 3000000
    
If this does not work directly, use:

    stty -F /dev/ttyUSB0 3000000
    btattach -B /dev/ttyUSB0

**2. Use with BlueZ**

Assuming that you already have a regular Bluetooth device, you new device is `hci1`.

    hciconfig hci1 up

You can list your HCI devices:

    hcitool dev

License
-------

Copyright 2019 Jiska Classen

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
