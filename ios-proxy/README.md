# internalblue-ios-proxy
This project is a proxy that redirects the *iOS* Bluetooth socket and exposes it as a
TCP socket which can be used to send HCI commands to the Bluetooth controller of the device.
A jailbroken device is required. To compile the project, a Mac with xcode is required.
The precompiled `ios-proxy` binary was tested on the iPhone 6 (12.1.2, 12.4), iPhone SE (12.4),
iPhone 7 (12.1.2, 12.4), and iPhone X (12.4).

## Building internalblue-ios-proxy
Open the project with xcode and compile it. Xcode will create a single binary that can then be transferred onto the device.

## Installing internalblue-ios-proxy
1. Right-click the `internalblue-ios-proxy` binary and click "Show in Finder". This will open the location the compiled binary resides in.
2. Move the binary onto the device (e.g. with scp) at a location where applications are allowed to be executed (e.g. `/bin` or `/sbin`).
3. The binary needs the `platform-application` entitlement. This is achieved by signing the binary with the included `entitlements.xml` file. Sign it using `ldid -Sentitlements.xml internalblue-ios-proxy`. `ldid` should be on a jailbroken device with Cydia by default.

## Running internalblue-ios-proxy
Run the proxy by executing `internalblue-ios-proxy <port-number>`.
The phone will then listen on this port and can be accessed either when on the same Wi-Fi or
by proxying the port through USB (using [usbmuxd](https://iphonedevwiki.net/index.php/SSH_Over_USB)).
When enabling a personal hotspot, you can also run `dhclient` on *Linux* on the new local ethernet interface.

A few things to note:
- To increase reliability of the proxy, *Bluetooth should be disabled*
  (either by manually stopping the Bluetooth daemon or by shutting of Bluetooth in the
  settings on the phone). Despite shutting down Bluetooth, the RAM will still have the same contents
  as during previous usage, and you can analyze it.
- The current implementation sometimes returns wrong results, thus we double-check results of 
  commands that read ROM/RAM. We show warnings, but firmware dumps should complete nonetheless.
- To get sufficient performance, access the `ios-proxy` over USB and not using Wi-Fi.
- In case the Bluetooth chip crashes or does not respond anymore over the proxy,
  the proxy should be stopped and Bluetooth should be turned off and on again in the UI.
- Sometimes the Bluetooth socket will not respond anymore after establishing a second connection,
  just restart the proxy then.

This project is based on Brandon Azad's [iOS command line tool](https://github.com/bazad/ios-command-line-tool) template.
