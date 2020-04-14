
Recent Changes
--------------
* We upgraded from Python 2 to Python 3. If you wrote your own scripts, this might break them. In this case, use
  the [python2](https://github.com/seemoo-lab/internalblue/releases/tag/python2) release.

* We reworked the *iOS* implementation.


Requirements
------------

#### Android
* Ideally recompiled `bluetooth.default.so`, but also works on any rooted smartphone, see [Android instructions](android_bluetooth_stack/README.md)
* Android device connected via ADB
* Best support is currently given for Nexus 5 / BCM4339
* Optional: Patch for Android driver to support Broadcom H4 forwarding
* Optional, if H4: Wireshark [Broadcom H4 Dissector Plugin](https://github.com/seemoo-lab/h4bcm_wireshark_dissector)

#### Linux
* BlueZ, instructions see [here](linux_bluez/README.md)
* Best support for Raspberry Pi 3/3+/4 and Cypress evaluation boards
* For most commands: Privileged access

#### iOS
* A jailbroken iOS device (tested on iOS 12 and 13 with iPhone 6, SE, 7, 8, X , does not work on iPhones newer than XR, these devices have a Bluetooth chip connected via PCIe)
* iOS 12 and 13 have been tested as of now
* `usbmuxd`, which is pre installed on macOS but is available on most Linux distributions as well. Alternatively it can be obtained from [here](https://github.com/libimobiledevice/usbmuxd).
* The [``internalblued`` daemon](ios/README.md) installed on the iOS device

* Optional, no jailbreak required: install [iOS Bluetooth Debug Profile](https://developer.apple.com/bug-reporting/profiles-and-logs/) to obtain
  HCI and diagnostic messages, either via diagnostic report feature (all iOS versions) or live with PacketLogger (since iOS 13)

#### macOS
* Homebrew
* Xcode 10.2.1
* Instructions see [here](macos.md)

Setup and Installation
----------------------

The framework uses __ADB__ (Android Debug Bridge) to connect to an Android
smartphone, __BlueZ__ sockets on Linux, the undocumented __IOBluetooth__ API on macOS, or the included __iOS Proxy__ on iOS.

For [Android](android_bluetooth_stack) with ADB, either connect the phone via USB or setup ADB over TCP and make sure you
enable USB debugging in the developer settings of Android.

If you have a jailbroken [iOS](ios.md) device, you need to install a proxy that locally connects
to the Bluetooth device and forwards HCI commands and events.

On [Linux](linux_bluez.md) with *BlueZ*, everything should work out of the box, but
you need to execute *InternalBlue* as root for most features.

The *InternalBlue* framework supports and requires Python 3.6 and above.


### Install from PyPI

Currently there is no package published on PyPI for Python 3, this will happen in the near future.


### Install as package from GitHub `master` or any other branch

```sh
pip install https://github.com/seemoo-lab/internalblue/archive/master.zip
```

This will download the contents of current master as a zip archive and install them via `pip`.
No local checkout of the git will exist.

If you want to update you need to run:

```sh
pip install --upgrade https://github.com/seemoo-lab/internalblue/archive/master.zip
```

### Development Install

If you except that you might want to read the code locally, debug it
or possibly change it you should setup an editable install.

```sh
git clone https://github.com/seemoo-lab/internalblue
cd internalblue
pip install --editable ./
```
Any changes to the python code in your git checkout will now be immediately reflected when importing `internalblue` or starting it from your shell.

You can now git pull, change branches or fork to submit your own branches:
```sh
git pull # Update current branch
git checkout origin/$featurebranch # Test some feature or bugfix branch
hub fork # requires https://github.com/cli/cli to be set up before
git checkout -b $your_new_feature_branch
```

### Dependencies

It will install the following dependencies:
* `pwntools`

The `pwntools` module needs the `binutils` package for ARM 32-bit to be installed
on the system. This has to be installed manually by using the packet manager
of your Linux distribution:

    # for Arch Linux
    sudo pacman -S arm-none-eabi-binutils

    # for Ubuntu
    sudo apt install binutils-arm-linux-gnueabi
    
All steps on a plain *Ubuntu 18.04*:

    sudo apt install git python-setuptools binutils-arm-linux-gnueabi adb pip python-dev gcc
    pip install --upgrade https://github.com/seemoo-lab/internalblue/archive/master.zip
    
    sudo apt-get install wireshark-dev wireshark cmake
    git clone https://github.com/seemoo-lab/h4bcm_wireshark_dissector
    cd h4bcm_wireshark_dissector
    mkdir build
    cd build
    cmake ..
    make
    make install

Packets required on a current (March 2020) *Raspbian*:
     
     sudo apt-get --allow-releaseinfo-change update
     sudo apt-get install git python3-setuptools binutils-arm-none-eabi adb python3-pip python3-dev gcc libffi-dev



Usage
-----

The CLI (Command Line Interface) of *InternalBlue* can be started by running:

    python -m internalblue.cli

The setup.py installation will also place a shortcut to the CLI into the `$PATH`
so that it can be started from a command line using:

    internalblue

It should automatically connect to your Android phone through ADB or your local *Linux*
with BlueZ. With BlueZ, some commands can be sent by unprivileged users (i.e. version
requests) and some commands require privileged users (i.e., establishing connections).
Use the `help` command to display a list of available commands. A typical set of
actions to check if everything is working properly would be:

    wireshark start
    connect ff:ff:13:37:ab:cd
    sendlmp 01 -d 02

Note that InternalBlue only displays 4 byte MAC addresses in some places. This is
because the leading two bytes are not required by Bluetooth communication, you
can replace them with anything you want.
