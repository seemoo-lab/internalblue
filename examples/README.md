InternalBlue PoCs and Examples
==============================

The following examples were tested on a *Nexus 5* (*BCM4339* chip with firmware *BCM4335C0*) on *Android* and *LineageOS*.

* [CVE_2018_5383_Invalid_Curve_Attack_PoC](CVE_2018_5383_Invalid_Curve_Attack_PoC.py)
  provides tries to set the y-coordinate during ECDH key exchange to zero. If the device under test accepts the pairing (50% probability), it is vulnerable.
* [LMP_MAC_Address_Filter](LMP_MAC_Address_Filter.py)
  replies to all LMP packets with `LMP_not_accepted` if their source is not from a MAC address in the whitelist.
* [NiNo_PoC](NiNo_PoC.py) sets the IO capabilities of the *Nexus 5* to no input, no output.

Examples for the Raspberry Pi 3:

* [raspi3_rxdn](raspi3_rxdn.py) prints the first bytes of the LE connection struct within the `_connTaskRxDone` callback.
  For debugging purposes, warnings are shown for packet failures. The full logging can be enabled via `log_level debug` on the
  *InternalBlue* command line. It contains the current channel, RSSI, and event number for each packet. To blacklist channels
  from hopping, use `sendhcicmd 0x2014 ff00000000` or similar. Use `wireshark` or `btmon`
  to see the channel blacklisting live within the connection struct.
  
  
Examples for the Samsung Galaxy S8:
* [s8_rxdn](s8_rxdn.py) same as for Raspberry Pi 3. Call *InternalBlue* with `internalblue -s` for serial setup.