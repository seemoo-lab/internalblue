InternalBlue PoCs and Examples
==============================


KNOB Attack Test (CVE-2019-9506)
--------------------------------
We provide a modified version of the KNOB attack test, originally provided [here](https://github.com/francozappa/knob).
This script tests if the other device will accept a reduced key entropy of 1 byte instead of the optimal 16 byte.
Available for the [Raspberry Pi 3](../examples/rpi3/KNOB_PoC.py), [Raspberry Pi 3+/4](../examples/rpi3p_rpi4/KNOB_PoC.py),
[Nexus 5](../examples/nexus5/KNOB_PoC.py), [Nexus 6P](../examples/nexus6p/KNOB_PoC.py), [CYW20735 evaluation board](../examples/eval_cyw20735/KNOB_PoC.py),
and [Samsung Galaxy S8](../examples/s8/KNOB_PoC.py).

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
some cases). If Bluetooth crashes, it is vulnerable. Currently only available for the
[Nexus 5](../examples/nexus5/CVE_2018_19860_Crash_on_Connect.py) and the [CYW20735 evaluation board](../examples/eval_cyw20735/CVE_2018_19860_Crash_on_Connect.py).

Invalid Curve Attack Test (CVE-2018-5383)
-----------------------------------------
This is a test which tires to set the y-coordinate during ECDH key exchange to zero. If the devie under test accepts the pairing
(50% probability), it is vulnerable. This is not an MITM implementation, it only tests, if the other device would be vulnerable in practice.

Available for the [Nexus 5](../examples/nexus5/CVE_2018_5383_Invalid_Curve_Attack_PoC.py).

LMP MAC Address Filter
----------------------
Only accept traffic from whitelisted MAC addresses and send `LMP_not_accepted` otherwise.

Available for the [Nexus 5](../examples/nexus5/LMP_MAC_Address_Filter.py).

NiNo Attack Test
----------------
Prior to pairing, an MITM can set the IO capabilities to no input, no output. This will skip the numeric comparison.
If the operating system displays a yes/no question during pairing, a warning, or similar, is up to the concrete implementation.
This script tests how the other device will behave in a pairing that does not use numeric comparison, but is no
active MITM attack.

Available for the [Nexus 5](../examples/nexus5/NiNo_PoC.py).


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