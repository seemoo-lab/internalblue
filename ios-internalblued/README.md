# internalblued 
This project is a proxy that redirects the *iOS* Bluetooth socket and exposes it as a
TCP socket which can be used to send HCI commands to the Bluetooth controller of the device.
A jailbroken device is required.

A compiled version of `internalblued` can be found in [`packages/com.ttdennis.internalblued_0.0.1_iphoneos-arm.deb`](packages/com.ttdennis.internalblued_0.0.1_iphoneos-arm.deb).

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

