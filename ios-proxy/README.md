# internalblue-ios-proxy
This project is a proxy that redirects iOS's bluetooth socket and exposes it as a TCP socket which can be used to send HCI commands to the bluetooth controller of the device. A jailbroken device is required. To compile the project, a Mac with xcode is required.

## Building internalblue-ios-proxy
Open the project with xcode and compile it. Xcode will create a single binary that can then be transferred onto the device.

## Installing internalblue-ios-proxy
1. Right-click the `internalblue-ios-proxy` binary and click "Show in Finder". This will open the location the compiled binary resides in.
2. Move the binary onto the device (e.g. with scp) at a location where applications are allowed to be executed (e.g. `/bin` or `/sbin`).
3. The binary needs the `platform-binary` entitlement. This is achieved by signing the binary with the included `entitlements.xml` file. Sign it using `ldid -Sentitlements.xml internalblue-ios-proxy`. `ldid` should be on a jailbroken device with Cydia by default.

## Running internalblue-ios-proxy
Run the proxy by executing `internalblue-ios-proxy <port-number>`. The phone will then listen on this port and can be accessed either when on the same WiFi or by proxying the port through USB (using [usbmuxd](https://iphonedevwiki.net/index.php/SSH_Over_USB)).

A few things to note:
- to increase reliability of the proxy, bluetooth should be disabled (either by manually stopping the bluetoothd daemon or by shutting of bluetooth in the settings on the phone)
- in case the bluetooth chip crashes or does not respond anymore over the proxy, the proxy should be stopped and bluetooth should be turned off and on again in the UI
- sometimes the bluetooth socket will not respond anymore after establishing a second connection, just restart the proxy then.

This project is based on Brandon Azad's [iOS command line tool](https://github.com/bazad/ios-command-line-tool) template.
