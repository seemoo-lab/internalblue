Happy MitM - Fun and Toys in Every Bluetooth Device
---------------------------------------------------

The Bluetooth 5.2 specification requires to warn the user upon authentication
failures (p. 1314). However, none of the current stacks implements this.

For a simple PoC, we temporarily change the link key when the chip requests
it via HCI. Note that **this PoC can also be used for various other HCI-based
experiments**, e.g., to test non-compliant chip behavior. As of now, these
scripts are based on Frida and available for Android and iOS.

You can find more details in our WiSec 2021 publication.

#### iOS PoC

As a proof of concept, we use Frida on an iPhone 8 with iOS 14.4 (same iOS as iPhone 7)
and switch the link key upon request. The [script](../examples/keychange/ios_keychange.js) can be called as follows:

```
frida -U bluetoothd --no-pause -l ios_keychange.js
```

Frida automatically applies changes to the script during runtime as soon as the
script changes, so it is possible to change `var swap_key = true;` to `false` and
just save the script to disable swapping the keys and just displaying them.

Of course, we could also try to make a perfect copy of the iPhone and create a
device with a similar MAC address. However, this also requires to set the same
IO capabilities and device properties and might introduce additional sources of
failure.


#### Android PoC

Our PoC also contains a [script](../examples/keychange/android_keychange.js) for an Android phone, the Samsung Galaxy Note20 5G
on a patchlevel of January 2021. However, since we hook into `libbluetooth.so` without
symbols this only works in this very specific version. Moreover, since Android loads all
link keys on Bluetooth initialization, one needs to disable and re-enable Bluetooth to
get the PoC working.

The PoC works for both BLE and Classic Bluetooth. BLE is best to be tested with the
nRF Connect app, since this supports separate bonding without downloading the actual app
of the BLE gadget.

Usage:

```
frida -U com.android.bluetooth --no-pause -l android_keychange.js
```


#### Linux PoC

For BlueZ, just replace the key in `/var/lib/bluetooth/mac1/mac2/info`.
`bluetoothd` needs to be restarted. Hooking with Frida didn't work within HCI because
BlueZ uses a separate management layer and `hci.c` only seems to be used by `hcitool`.
The management layer is described in `doc/mgmt-api.txt` and has commands to load all
link keys and all long term keys (*Load Link Keys Command*, *Load Long Term Keys Command*),
which are issued during startup and read from `/var/lib/bluetooth`. Thus, we could hook
the management interface from userspace, but that wouldn't add any value to *InternalBlue*
later on.

Some more details on the Linux BlueZ architecture that are relevant for this are
also described in this [blog post](https://naehrdine.blogspot.com/2021/03/bluez-linux-bluetooth-stack-overview.html).
