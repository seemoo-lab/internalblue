InternalBlue PoCs and Examples
==============================


KNOB Attack Test (CVE-2019-9506)
--------------------------------
We provide a modified version of the KNOB attack test, originally provided [here](https://github.com/francozappa/knob).
This script tests if the other device will accept a reduced key entropy of 1 byte instead of the optimal 16 byte.
Available for the [Raspberry Pi 3](rpi3/KNOB_PoC.py), [Raspberry Pi 3+/4](rpi3p_rpi4/KNOB_PoC.py), [Nexus 5](nexus5/KNOB_PoC.py), [CYW20735 evaluation board](eval_cyw20735/KNOB_PoC.py), and [Samsung Galaxy S8](s8/KNOB_PoC.py).


Invalid Curve Attack Test (CVE-2018-5383)
-----------------------------------------
This is a test which tires to set the y-coordinate during ECDH key exchange to zero. If the devie under test accepts the pairing
(50% probability), it is vulnerable. This is not an MITM implementation, it only tests, if the other device would be vulnerable in practice.

Available for the [Nexus 5](nexus5/CVE_2018_5383_Invalid_Curve_Attack_PoC.py).

LMP MAC Address Filter
----------------------
Only accept traffic from whitelisted MAC addresses and send `LMP_not_accepted` otherwise.

Available for the [Nexus 5](nexus5/LMP_MAC_Address_Filter.py).

NiNo Attack Test
----------------
Prior to pairing, an MITM can set the IO capabilities to no input, no output. This will skip the numeric comparison.
If the operating system displays a yes/no question during pairing, a warning, or similar, is up to the concrete implementation.
This script tests how the other device will behave in a pairing that does not use numeric comparison, but is no
active MITM attack.

Available for the [Nexus 5](NiNo_PoC.py).

