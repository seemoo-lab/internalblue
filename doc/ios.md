# internalblued 
This project is a proxy that redirects the *iOS* Bluetooth socket and exposes it as a
TCP socket which can be used to send HCI commands to the Bluetooth controller of the device.
A jailbroken device is required.

A compiled version of `internalblued` can be found in [`packages/com.ttdennis.internalblued_0.0.1_iphoneos-arm.deb`](../ios/packages/com.ttdennis.internalblued_0.0.1_iphoneos-arm.deb).

## Installing
1. Transfer the `.deb` file to your iOS device
2. Run `dpkg -i your-deb-file.deb` to install `internalblued` on your device

## Running internalblued
Once installed, `internalblued` runs as a `LaunchDaemon` and is ready to be used. By default it will listen to port 1234 (TCP) on localhost. If `usbmux` is installed, `internalblue` will be able to connect to the phone as the port is passed through `usbmuxd`.

During usage with `internalblue` Bluetooth has to be disabled in the phones Settings App.

In case the Bluetooth chip stops responding, Bluetooth has to be turned on and off again in the Settings App.

There is a Settings App pane for `internalblued` to turn off the daemon and adapt the listening port. However, this is usually not required. As long as `internalblue` is not connected to `internalblued`'s socket, Bluetooth can be used without any restrictions.

## Building internalblued
1. Install [theos](https://github.com/theos/theos)
2. Run `make`
3. A `.deb` file should be in the `packages` folder now


## BlueTool

More inconvenient to use, but still an option on the PCIe *iPhone XS* and *iPhone 11*, is `BlueTool`.
It can even be scripted, but the scripts must be located in `/etc/bluetool`.

For example, during our Random Number Generator (RNG) tests, we used the following commands
to access the RNG area and execute the `LE_Rand` HCI command. Note that the input must be
decimal but the output is hexadecimal. Similar to `internalblued`, `BlueTool` can only
run while Bluetooth is turned off.

```
device -D
hci cmd 0xfc4d 0 38 96 0 32
  HCI Command Response: 01 4D FC 00 03 00 00 00 01 00 00 02 DC 70 02 76 77 77 77 77 77 77 77 77 00 00 00 00 00 00 00 00 00 00 00 00 
hci cmd 0x2018
  HCI Command Response: 01 18 20 00 2A FC 1F 73 67 11 06 F9
```

## Bypassing the WriteRAM Restriction 

After iOS 13.3, WriteRAM is blocked. This is part of the Spectra mitigation and should prevent 
an attacker with control over `bluetoothd` to escalate into the Wi-Fi chip (yes, Wi-Fi, not Bluetooth, this is
no typo). Re-enabling WriteRAM poses a security risk but is required for experimentation.

The security patch blocks the WriteRAM command to just return the status 0x12 instead of executing it.
Starting from iOS 13.6, `.hcd` files are no longer in the firmware directory but built-in into `BlueTool`.

The patch we want to undo looks like this:
```
ROM:00146176 4C 2D                       CMP     R5, #0x4C ; 'L' ; fc4c: VSC_Write_RAM -> Block this
ROM:00146178
ROM:00146178             loc_146178                              ; CODE XREF: bthci_cmd_HandleCommand+B0↓j
ROM:00146178                                                     ; bthci_cmd_HandleCommand+B4↓j
ROM:00146178 08 D0                       BEQ     loc_14618C
ROM:0014617A 08 DC                       BGT     loc_14618E
ROM:0014617C 0A 2D                       CMP     R5, #0xA        ; fc0a: VSC_Super_Peek_Poke
```

We can simply replace the `0x4c`, which is the WriteRAM command, with `0x42`, which is not used.
Note that `BlueTool` contains multiple copies of these `.hcd` files and you should replace all of them.
The accordingly modified `BlueTool` needs to be copied to `/usr/sbin/BlueTool` and `/usr/sbin/BlueTool.sbin`.
To get Bluetooth working properly again after replacing `BlueTool`, the iPhone needs to be rebooted.


**Bluetooth will only work while the device is jailbroken with a modified BlueTool version!
Use at your own risk and make a backup of the original.** Without jailbreak, the integrity check
for `BlueTool` seems to fail and Bluetooth is constantly restarting.

[BlueTool for iOS 13.6 on an iPhone 8](../ios/BlueTool_iPhone8_iOS13.6), might also work on other <A12 devices.