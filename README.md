![InternalBlue](doc/images/internalblue_text.svg)


*Broadcom* chips are used in approximately a billion of devices, such as
all *iPhones*, *MacBooks*, the *Samsung Galaxy S* series, the older *Google
Nexus* series, older *Thinkpads*, *Raspberry Pis*, various IoT devices, and more.
In 2016, *Cypress* acquired the IoT division of *Broadcom*. Since
then, firmware variants slightly diverged, as *Broadcom* kept non-IoT customers like
*Apple* and *Samsung*. However, the firmware interaction
and update mechanism stayed the same. We reverse-engineered how the operating
systems patch this firmware and interact with it. Based on that we developed a
Bluetooth experimentation framework, which is able to patch the firmware.
This enables various features that otherwise would only be possible with
a full-stack software-defined radio implementation, such as injecting and
monitoring packets on the link layer.

*InternalBlue* has not only been used for our own research at the Secure Mobile
Networking Lab ([SEEMOO](https://seemoo.de)). Also, the [KNOB](https://knobattack.com/) and [BIAS](https://francozappa.github.io/about-bias/) attack prototype 
were implemented using *InternalBlue* LMP messages
and the [SweynTooth](https://asset-group.github.io/disclosures/sweyntooth/) attacks also
experimented with *InternalBlue* for crafting LCP messages. Note that in contrast to tools like
[btlejack](https://github.com/virtualabs/btlejack) or
[Ubertooth](https://github.com/greatscottgadgets/ubertooth), *InternalBlue* does not
aim at performing Machine-in-the-Middle attacks. However, the device running *InternalBlue*
can send arbitrary packets and also inject these into existing connections. During
monitoring, all packets that are received by the device running *InternalBlue* are
captured, and there is no packet loss. *InternalBlue* does not have any issues with analysis of encrypted connections or
Classic Bluetooth. If you have specific feature requests for your security research,
feel free to open a ticket.

In addition to security research, *InternalBlue* also opens possibilities for
further analysis such as Bluetooth Low Energy performance statistics and improvements.
Anything that can be improved within a Bluetooth stack can be directly tested on
off-the-shelf devices.

Our recent research features [Frankenstein](https://github.com/seemoo-lab/frankenstein),
which emulates the firmware including thread switches and virtual modem input. The
emulated firmware can be attached to a *Linux* host. Thus, the approach is full-stack.
We mainly used it for fuzzing and found vulnerabilities that include host responses
to be triggered. *Frankenstein* is in a separate repository, but depends on *InternalBlue*
to take state snapshots etc. on a physical device.

Moreover, we just published [Polypyus](https://github.com/seemoo-lab/polypyus).
It enables binary-only binary diffing, independent from *IDA* and *Ghidra*. However,
it integrates into that workflow by identifying good starting points for further
analysis. We already tried it across various *Broadcom* Wi-Fi and Bluetooth firmware.

Looking for our random number generator measurements that we did within the analysis
of CVE-2020-6616? You can find them [here](doc/rng.md).

Due to Spectra 👻🌈 the write and read RAM commands are disabled after driver initialization.
Workarounds for this are described in the according *Android* and *iOS* instructions,
bypasses for other devices will follow if needed. 



Table of Contents
-----------------
* [Feature overview](doc/features.md)
* [General setup and usage](doc/setup.md)
* Operating system specific setup
    * [Android](doc/android.md) *6—10 (rooted)*
    * [iOS](doc/ios.md) *12—14 (jailbroken)*
    * [macOS](doc/macos.md) *High Sierra—Big Sur*
    * [Linux](doc/linux_bluez.md) with *BlueZ* (default) but __not__ WSL
* [Firmware overview](doc/firmware.md)
* [SEEMOO talks and publications](doc/publications.md)
* [Examples](doc/examples.md)










License
-------

Copyright 2018-2020 The InternalBlue Team

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
