InternalBlue PoCs and Examples
==============================

All examples were tested on a *Nexus 5* (*BCM4339* chip with firmware *BCM4335C0*) on *Android* and *LineageOS*.

* [CVE_2018_5383_Invalid_Curve_Attack_PoC](CVE_2018_5383_Invalid_Curve_Attack_PoC.py)
  provides tries to set the y-coordinate during ECDH key exchange to zero. If the device under test accepts the pairing (50% probability), it is vulnerable.
* [LMP_MAC_Address_Filter](LMP_MAC_Address_Filter.py)
  replies to all LMP packets with `LMP_not_accepted` if their source is not from a MAC address in the whitelist.
* [NiNo_PoC](NiNo_PoC.py) sets the IO capabilities of the *Nexus 5* to no input, no output.