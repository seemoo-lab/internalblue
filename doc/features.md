Supported Features
------------------

This list is subject to change, but we give you a brief overview.
You probably have a platform with a *Broadcom* chip that supports most features :)

On any Bluetooth chip:
* Send HCI commands
* Monitor HCI
* Establish connections

On any Broadcom Bluetooth chip:
* Read and write RAM
* Read and write assembly to RAM
* Read ROM
* Set defined breakpoints that crash on execution
* Inject arbitrary valid LMP messages (opcode and length must me standard compliant, contents and order are arbitrary)
* Use diagnostic features to monitor LMP and LCP (with new **Android** H4 driver patch, still needs to be integrated into BlueZ)
* Read AFH channel map

On selected Broadcom Bluetooth chips:
* Write to ROM via Patchram (any chip with defined firmware file >= build date 2012)
* Interpret core dumps (Nexus 5/6P, Samsung Galaxy S6, Evaluation Boards, Samsung Galaxy S10/S10e/S10+)
* Debug firmware with tracepoints (Nexus 5 and Evaluation Board CYW20735)
* Fuzz invalid LMP messages (Nexus 5 and Evaluation Board CYW20735)
* Inject LCP messages, including invalid messages (Nexus 5, Raspberry Pi 3/3+/4) 
* Full object and function symbol table (Cypress Evaluation Boards only)
* Demos for Nexus 5 only:
  * ECDH CVE-2018-5383 example
  * NiNo example
  * MAC address filter example
* KNOB attack test for various devices, including Raspberry Pi 3+/4
* BLE reception statistics
