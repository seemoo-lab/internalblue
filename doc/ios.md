## Installation of internalblued on iOS

This project is a proxy that redirects the *iOS* Bluetooth socket and exposes it as a
TCP socket which can be used to send HCI commands to the Bluetooth controller of the device.
A jailbroken device is required.

A compiled version of `internalblued` can be found in [`ios/packages/com.ttdennis.internalblued_0.0.1_iphoneos-arm.deb`](../ios/packages/com.ttdennis.internalblued_0.0.1_iphoneos-arm.deb)
for UART devices and in [`ios-pcie/packages/com.ttdennis.internalblued_0.0.1-54+debug_iphoneos-arm.deb)`](../ios-pcie/packages/com.ttdennis.internalblued_0.0.1-54+debug_iphoneos-arm.deb)
for PCIe devices.

UART devices:
* iPhone 6
* iPhone 7
* iPhone SE
* iPhone 8
* iPhone XR (yes, even though this one is already A12) (not tested)

PCIe devices:
* iPhone Xs (not tested)
* iPhone 11
* iPhone SE2
* iPhone 12
* iPhone 13 (same as iPhone 12)


1. Transfer the `.deb` file to your iOS device
2. Run `dpkg -i your-deb-file.deb` to install `internalblued` on your device

The installer depends on `jtool2`, which can be downloaded [here](http://www.newosxbook.com/tools/jtool.html)
or from the [kiiimo](http://cydia.kiiimo.org/) repo via Cydia.

On *Linux*, `libimobiledevice` bindings see to be slightly different and you might to adjust the following line:
```
dev_id = "iOS Device (" + dev.serial.decode('utf-8') + ")" 
```

## Running internalblued
Once installed, `internalblued` runs as a `LaunchDaemon` and is ready to be used. By default it will listen to port 1234 (TCP) on localhost. If `usbmux` is installed, `internalblue` will be able to connect to the phone as the port is passed through `usbmuxd`.

During usage with `internalblue` Bluetooth has to be disabled in the phones Settings App.

In case the Bluetooth chip stops responding, Bluetooth has to be turned on and off again in the Settings App.

There is a Settings App pane for `internalblued` to turn off the daemon and adapt the listening port. However, this is usually not required. As long as `internalblue` is not connected to `internalblued`'s socket, Bluetooth can be used without any restrictions.


## Bypassing WriteRAM Restriction on PCIe iPhones (unc0ver)

Same principle but the firmware has checksums. Thanks to r0bre we how have
[fpibro.py](https://github.com/seemoo-lab/frankenstein/blob/master/projects/BCM4387C2/ios_scripts/fpibro.py),
which is capable of fixing these after modification.

Instead of overwriting the file, copy it to the `/tmp` folder and load it with `BlueTool`.
Everything else will bootloop an A12+ device (see above).

```commandline
power off
device -D
bcm -w /tmp/firmware.bin
```

None of the commands should return an error (e.g., no `bcm returned -1` error etc.).

***iPhone 12+13***

Hazelnut firmware with a WriteRAM bypass, compatible with iPhone 12+13:
[Hazelnut_iPhone12+13_iOS15.2.bin](../ios-pcie/firmware/Hazelnut_iPhone12+13_iOS15.2.bin),
will also work on jailbroken iOS 14.x iPhone 12.

Firmware modification and writing patches in C is supported as part of Frankenstein.
Tooling and symbols for the [BCM4387C2](https://github.com/seemoo-lab/frankenstein/tree/master/projects/BCM4387C2)
chip are available to perform research on the iPhone 12 and 13.


***iPhone 11+SE2020***

Moana (iPhone 11) firmware with a WriteRAM bypass, compatible with iPhone 11+SE2020:
[Moana_iPhone11+SE2_iOS15.bin](../ios-pcie/firmware/Moana_iPhone11+SE2_iOS15.bin),
will also work with jailbroken iOS 14.x on iPhone SE2020.



## Bypassing the WriteRAM Restriction on UART iPhones (checkm8)

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
To get Bluetooth working properly again after replacing `BlueTool`, run:

```commandline
killall -9 bluetoothd internalblued BlueTool
```
Then, start a new *InternalBlue* Session.


**Bluetooth will only work while the device is jailbroken with a modified BlueTool version!
Use at your own risk and make a backup of the original.** Without jailbreak, the integrity check
for `BlueTool` fails. **You can only reboot the device in this state with checkm8, your device will
be bricked if you do this on unthethered jailbreaks like unc0ver!** You can still unbrick it by re-flashing
iOS, but if you did not have a blob backup, you'll need to upgrade it to the latest signed iOS version.

[BlueTool for iOS 13.6 on an iPhone 8](../ios/firmware/BlueTool_iPhone8_iOS13.6), might also work on other pre-A12 devices.
[BlueTool for iOS 14.3 on an iPhone 7+8](../ios/firmware/BlueTool_iPhone7+8_iOS14.3), might also work on other pre-A12 devices.
[BlueTool for iOS 14.7 on an iPhone 7+8](../ios/firmware/BlueTool_iPhone7+8_iOS14.7), might also work on other pre-A12 devices.


## Building internalblued (optional)

1. Install [theos](https://github.com/theos/theos)
2. Install the correct version of PrivateFramework header files (e.g. from [here](https://github.com/xybp888/iOS-SDKs)) for your build into your SDK
3. Run `make package`
4. A `.deb` file should be in the `packages` folder now



## BlueTool

Instead of using InternalBlue, it is also possible to use Apple's undocumented internal
tool `BlueTool`. It is way more inconvenient to use, has a lot of commands that will not show
in the help menu, and easily crashes when using it inappropriately. Apple does not consider
this to be an issue, since `BlueTool` cannot be called from sandboxed processes.

If you consider using `BlueTool` instead of InternalBlue, e.g., because your device is not
yet supported, you can even script it. All scripts must be located in `/etc/bluetool`.

For example, during our Random Number Generator (RNG) tests, we used the following commands
to access the RNG area and execute the `LE_Rand` HCI command. Note that the input must be
decimal but the output is hexadecimal. Similar to `internalblued`, `BlueTool` can only
run while Bluetooth is turned off.

```commandline
device -D
hci cmd 0xfc4d 0 38 96 0 32
  HCI Command Response: 01 4D FC 00 03 00 00 00 01 00 00 02 DC 70 02 76 77 77 77 77 77 77 77 77 00 00 00 00 00 00 00 00 00 00 00 00 
hci cmd 0x2018
  HCI Command Response: 01 18 20 00 2A FC 1F 73 67 11 06 F9
```