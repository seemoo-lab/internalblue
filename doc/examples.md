InternalBlue PoCs and Examples
==============================

MagicPairing PoCs
-----------------

The [magicpairing](../examples/magicpairing/README.md) folder contains the proof-of-concepts belonging
to our WiSec paper 
[MagicPairing: Apple's Take on Securing Bluetooth Peripherals](https://arxiv.org/abs/2005.07255).
For more information on the individual bugs, please refer to our paper.
This is what the PoC looks like:

```
    =>  1) [MP1]: iOS RatchetAESSIV Crash (0xa8)
        2) [MP2]: iOS Hint Crash (0x1)
        3) [MP3]: macOS RatchetAESSIV Crash (0x0)
        4) [MP4]: macOS Hint Crash (0x0)
        5) [MP5]: iOS RatchetAESSIV Crash (0x10d)
        6) [MP6]: iOS RatchetAESSIV Assertion Failure Crash
        7) [MP7]: macOS Ratcheting Loop DoS
        8) [MP8]: MagicPairing Lockout - NOT IMPLEMENTED HERE
        9) [L2CAP1]: AirPods L2CAP Crash
       10) [L2CAP2]: Group Reception Handler NULL-Pointer Jump (Classic Version)
       11) [L2CAP2]: Group Reception Handler NULL-Pointer Jump (BLE Version)
```


HRNG and PRNG Measurements (CVE-2020-6616)
------------------------------------------
The *Dieharder* test suite requires at least 1GB of data to decide if a RNG returned random numbers.
We provide all scripts we used to evaluate the HRNG and PRNG on various *Broadcom* and *Cypress*
chips. These can be adapted for tests on further platforms if needed.
Extracting so much from a Bluetooth chip requires a number of optimizations, which are also
interesting for other scripts. All measurements scripts contain custom HCI event callbacks, and
five of them contain a `Launch_RAM` fix (*Nexus 6P*, *iPhone 7*, *CYW20719*, *CYW20735*, *CYW20819*).
Also, these scripts document where we found some free memory chunks, which might also be helpful for
other implementations.
For some devices, we only checked if the firmware is indeed accessing a HRNG, thus, we provide less
than 20 scripts in total.

* Nexus 5: [PRNG](../examples/nexus5/randp.py), [HRNG](../examples/nexus5/rand.py)
* Nexus 6P/Samsung Galaxy S6: [PRNG](../examples/nexus6p/randp.py), [HRNG](../examples/nexus6p/rand.py)
* CYW20719 evaluation board: [PRNG](../examples/eval_cyw20719/randp.py), [HRNG](../examples/eval_cyw20719/rand.py)
* CYW20735 evaluation board: [HRNG](../examples/eval_cyw20735/rand.py) (didn't measure PRNG as HRNG was used)
* CYW20819 evaluation board: [PRNG](../examples/eval_cyw20819/randp.py), [HRNG](../examples/eval_cyw20819/rand.py)
* Raspberry Pi 3/Zero W: [PRNG](../examples/rpi3/randp.py), [HRNG](../examples/rpi3/rand.py)
* Raspberry Pi 3+/4: [PRNG](../examples/rpi3p_rpi4/randp.py), [HRNG](../examples/rpi3p_rpi4/rand.py)
* iPhone 6: [PRNG](../examples/iphone6/randp.py), [HRNG](../examples/iphone6/rand.py)
* iPhone 7: [HRNG](../examples/iphone7/rand.py) (didn't measure PRNG as HRNG was used)
* Samsung Galaxy S8: [PRNG](../examples/s8/randp.py) __(no HRNG present)__


We also have a [full list of firmware and hardware analysis results](rng.md) of the HRNG and PRNG.



KNOB Attack Test (CVE-2019-9506)
--------------------------------
We provide a modified version of the KNOB attack test, originally provided [here](https://github.com/francozappa/knob).
This script tests if the other device will accept a reduced key entropy of 1 byte instead of the optimal 16 byte.
Available for:

 * [Raspberry Pi 3](../examples/rpi3/KNOB_PoC.py)
 * [Raspberry Pi 3+/4](../examples/rpi3p_rpi4/KNOB_PoC.py)
 * [Nexus 5](../examples/nexus5/KNOB_PoC.py)
 * [Nexus 6P](../examples/nexus6p/KNOB_PoC.py)
 * [CYW20735 evaluation board](../examples/eval_cyw20735/KNOB_PoC.py)
 * [Samsung Galaxy S8](../examples/s8/KNOB_PoC.py)

LMP to HCI Handler Escalation Attack Test (CVE-2018-19860)
----------------------------------------------------------
This is an easy-to-use PoC for CVE-2018-19860. It sends multiple LMP messages with opcode 0 (Broadcom vendor-specific).
If the following byte, the vendor-specific opcode, is out of range of BPCS (larger than 6), vulnerable devices
interpret the memory located after the LMP BPCS handler table as further handlers. On many devices, HCI handlers
are located here, which lets an attacker call HCI via LMP, thus, resulting in limited code execution capabilities.
Invalid "handler" addresses in that memory range or invalid parameters passed to HCI handlers will cause Bluetooth
on the device under attack to crash. This PoC installs an Assembly snippet that sends multiple invalid LMP BPCS packets
before establishing connections. If an attacker connects to the device under test using the normal Android/Linux user
interface and the connection succeeds, the device is likely not vulnerable (you need to adapt the BPCS range in
some cases). If Bluetooth crashes, it is vulnerable. Currently only available for:

* [Nexus 5](../examples/nexus5/CVE_2018_19860_Crash_on_Connect.py)
* [CYW20735 evaluation board](../examples/eval_cyw20735/CVE_2018_19860_Crash_on_Connect.py)

Invalid Curve Attack Test (CVE-2018-5383)
-----------------------------------------
This is a test which tires to set the y-coordinate during ECDH key exchange to zero. If the devie under test accepts the pairing
(50% probability), it is vulnerable. This is not an MITM implementation, it only tests, if the other device would be vulnerable in practice.

* [Nexus 5](../examples/nexus5/CVE_2018_5383_Invalid_Curve_Attack_PoC.py)

LMP MAC Address Filter
----------------------
Only accept traffic from whitelisted MAC addresses and send `LMP_not_accepted` otherwise.

* [Nexus 5](../examples/nexus5/LMP_MAC_Address_Filter.py)

NiNo Attack Test
----------------
Prior to pairing, an MITM can set the IO capabilities to no input, no output. This will skip the numeric comparison.
If the operating system displays a yes/no question during pairing, a warning, or similar, is up to the concrete implementation.
This script tests how the other device will behave in a pairing that does not use numeric comparison, but is no
active MITM attack.

* [Nexus 5](../examples/nexus5/NiNo_PoC.py)


Measurement of BLE Receive Statistics
-------------------------------------
This demo provides a hook within the callback for BLE packet reception. Upon packet reception, no matter if the
packet is a keep-alive null packet or not, it will be processed by this function. During this state, further
metadata is available, such as the RSSI (Received Signal Strength Indicator), the packet's channel, and the
currently active channel map.

Available for the [Nexus 5](../examples/nexus5/BLE_Reception_PoC.py) and [Samsung Galaxy S8](../examples/s8/BLE_Reception_PoC.py) including a callback script,
as well as for the [CYW20735 Evaluation board](../examples/eval_cyw20735/BLE_Reception_PoC.py), [Raspberry Pi 3](../examples/rpi3/BLE_Reception_PoC.py)
and [3+/4](../examples/rpi3p_rpi4/BLE_Reception_PoC.py) currently without callback script.
We also ported it for the iPhone 6, however, the current *InternalBlue* iOS implementation cannot be run in parallel
with the full iOS stack, thus it is not pushed online here.