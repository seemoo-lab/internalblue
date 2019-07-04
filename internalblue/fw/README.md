Firmware Versions
=================

This package adds support for different Broadcom and Cypress firmware versions.
A list of known versions can be found below, however we only have firmware information on a subset of these.
Results are based on real world testing, this list is very incomplete. If you know more versions, input is appreciated.



Vendor | Version | SubVersion | Firmware    | Devices | Firmware Build Date
-------| ------- | ---------- | ----------- | ------- | ----------
0x000f |    0x04 |     0x4217 | BCM4329B1   | iPhone 4
0x000f |    0x04 |     0x21d0 | BCM2046     | iMac 27" late 2009 
0x000f |    0x04 |     0x422a | BCM4331     | MacBook Pro early 2011
0x000f |    0x05 |     0x4203 | BCM2034B    | Thinkpad T420
0x000f |    0x05 |     0x610d |             | iPad A1395
0x000f |    0x06 |     0x220e | BCM20702A1  | Asus USB Bluetooth dongle
0x000f |    0x06 |     0x229b | BCM20702A3  | MacBook Pro 13" mid 2012 (A1278)
0x000f |    0x06 |     0x4103 | BCM4330B1   | iPhone 4s
0x000f |    0x06 |     0x4196 | BCM20702B0  | MacBook Pro mid 2014, iMac (Retina 5k, 27", ultimo 2014)
0x000f |    0x07 |     0x220f | BCM20736S   | Equiva Radiator Thermostat CC-RT-BLE-EQ
0x000f |    0x07 |     0x2203 | BCM43342    | iPhone 5s
0x000f |    0x07 |     0x2209 | BCM43430A1  | Raspberry Pi 3 | Jun 2 2014
0x000f |    0x07 |     0x230f | BCM4356A2   | Xperia Z5
0x000f |    0x07 |     0x410d | BCM4334     | iPhone 5 (A1429)
0x000f |    0x07 |     0x6109 | BCM4335C0 (BCM4339) | Nexus 5, Xperia Z3 Compact, Samsung Galaxy Note 3, LG G4 (LG-h815), Samsung Galaxy Note 10.1 2014 WiFi (SM-P600) | Dec 11 2012
0x000f |    0x08 |     0x6119 | BCM4345C0   | Raspberry Pi 3+, Honor 8 | Aug 19 2014
0x000f |    0x08 |     0x21a1 |             | MacBook Pro Retina 13" early 2015 
0x000f |    0x08 |     0x21a6 | BCM20703A1  | MacBook Pro early 2015
0x000f |    0x08 |     0x21a7 | BCM20703A1  | MacBook Pro early 2015 (with security fix)
0x000f |    0x08 |     0x220b | BCM20707    | Fitbit Ionic 
0x000f |    0x08 |     0x2230 | BCM20703A2  | MacBook Pro 2016 (A1707) | Oct 22 2015
0x000f |    0x08 |     0x2246 | BCM20703A2  | MacBook Pro 2016
0x000f |    0x08 |     0x2247 | BCM20703A2  | MacBook Pro 2016 (with security fix)
0x000f |    0x08 |     0x224b | BCM20703A2  | MacBook Pro 2016, 2017
0x000f |    0x08 |     0x240f | BCM4358A3   | Nexus 6P, Samsung Galaxy S6, Samsung Galaxy S6 edge | Oct 23 2014 
0x000f |    0x08 |     0x4109 | BCM4345     | iPhone 6
0x000f |    0x08 |     0x430a |             | iPad Pro 2016 (MLMW2FD/A)
0x000f |    0x08 |     0x6103 | BCM4355C0   | iPhone 7 (A1778) | Sep 14 2015
0x000f |    0x08 |     0x6106 |             | Samsung Galaxy S7
0x000f |    0x08 |     0x617e | BCM4350     | MacBook Pro 2017 (Retina 12"), MacBook Pro (13", 2016)
0x000f |    0x08 |     0x6206 |             | iPhone SE
0x000f |    0x09 |     0x103f | BCM4364     | iMac Pro 2017
0x000f |    0x09 |     0x203f | BCM4364     | MacBook Pro (13", 2018)
0x000f |    0x09 |     0x2040 |             | Apple Watch Series 3
0x0131 |    0x09 |     0x4208 | CYW20819A1  | ULP BLE/BR/EDR Bluetooth 5 Wireless MCU Evaluation Kit CYW920819EVB-02 | May 22 2018
0x000f |    0x09 |     0x411a | BCM4347B0 (BCM4361B0) | Samsung Galaxy S8 | Jun 3 2016
0x0131 |    0x09 |     0x4208 | CYW20735B1  | BLE/BR Bluetooth 5.0 Evaluation Kit CYW920735Q60EVB-01 | Jan 18 2018
0x000f |    0x09 |     0x4208 | BCM4375B1   | Samsung Galaxy S10e, Samsung Galaxy S10, Samsung Galaxy S10+  (local version is 0x1111) | April 13 2018
0x000f |    0x09 |     0x420e |             | iPhone XR, iPhone X
0x0131 |    0x09 |     0x420e | CYW20739B1  | Bluetooth 5.0 BLE Evaluation Kit CYW920719Q40EVB-01 | Jan 17 2017
0x000f |    0x09 |     0x4307 |             | iPhone XS, iPhone Xs Max
0x000f |    0x09 |     0x4309 |             | Samsung Galaxy Note 9, Samsung Galaxy S9+




Matching of vendor and version number see list of [Bluetooth versions](https://www.bluetooth.com/specifications/assigned-numbers/link-manager) and [company identifiers](https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers).

There are more popular devices with Broadcom chips, i.e. many Lenovos, Acers, Sonys, Toshibas, HPs, Azurewares, ... see [this list](https://github.com/winterheart/broadcom-bt-firmware/blob/master/DEVICES.md), but we did not see these in the wild yet and do not know their LMP subversion.  


Known Issues
------------

There is a couple of issues causing trouble running *InternalBlue*, which are related to certain firmware versions.

* BCM4335C0
  * Diagnostic messages lack behind by one. If you send `diag c1` you will not get a response. Followed by `diag c2` you will get a response for `c1`, and so on. This issue is independent from the Android driver patch, i.e. a Nexus 6P works perfectly with the same LineageOS 14.1 patch that causes this issue on a Nexus 5. 
* BCM4358A3
  * `Launch_RAM` crashes the firmware if it received another HCI command within the next ~6 seconds. When patching and launching scripts, close the Bluetooth overview from the operating system to prevent scanning and hope that nothing else interacts with this. 
* CYW20735B1
  * `Launch_RAM` works in principle, but threading seems to be broken if the executed code generates other HCI events.
  A hook at `0xB0316` is a nice spot to implement a function that generates HCI events and can be called via the HCI command `0xfc19`.
  
Firmware Version and Build Date
-------------------------------

Broadcom internally uses different firmware versions than chip names. For example, the *BCM4339* chip in the *Nexus 5* 
is internally called *BCM4335C0*. It is known to be a revision of the older *BCM4335* chip.

On newer chips, the build information is located in the beginning of the stack. To see it, simply enter

    hd 0x200400
   


Firmware Related Setup
----------------------
The following steps are required to use the CYW20735B1 evaluation kit as normal HCI device on Linux with BlueZ.
 

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

**3. Command line tools for connections**

Scanning for devices:

    hcitool scan
    hcitool lescan

Connections and pairing:

    bluetoothctl

Enter into `bluetoothctl` command prompt:

    power on
    agent on
    default-agent
    scan on

Optional - accept connections:

    advertise on
    pairable on
    discoverable on

Do a pairing and then connect:

    pair aa:bb:cc:dd:ee:ff
    connect aa:bb:cc:dd:ee:ff
    
    
    

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
