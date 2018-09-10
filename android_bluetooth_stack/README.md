Enable Debugging Features in the Android Bluetooth Stack
========================================================

The Android Bluetooth stack has [debugging features](https://chromium.googlesource.com/aosp/platform/system/bt/+/master/doc/network_ports.md)
which are disabled in normal builds. To enable them, the Bluetooth Stack
(*bluetooth.default.so*) has to be build with debugging preprocessor defines.

This tutorial shows how to compile and install such a debugging Bluetooth Stack.
Inside this directory are also several precompiled Bluetooth Stacks which have
been created according to the tutorial below. You can skip the build if you
happen to have a device for which a precompiled *bluetooth.default.so* exists.


Build (AOSP)
------------

In order to build a custom Bluetooth stack with enabled debugging features for
Android it is necessary to setup a build environment for the AOSP. In recent
versions of Android the Bluetooth stack can also be built as standalone
project. However, this guide explains the build process for the Nexus 5 running
Android 6.0.1 which requires the complete AOSP build setup. The build process of
an Android ROM needs around 100 GB of storage for the source tree and the
compiled outputs.

Most steps of this tutorial are taken from an online [tutorial from
Sony](https://developer.sonymobile.com/open-devices/aosp-build-instructions/how-to-build-aosp-marshmallow-for-unlocked-xperia-devices/).
For the most recent Android version (at the time this tutorial was written the
most recent Android version is 8.1) there exist preconfigured [AWS
instances](https://aws.amazon.com/marketplace/pp/B01AOKYCZY) which come with
the latest AOSP repository and all necessary tools installed. However, for a
significantly older version, it is easier to setup a fresh instance with an
older Ubuntu version to get all necessary tools (Java, gcc, etc.) in their
correct versions. The instance should have high network throughput, fast
storage (dedicated SSD) and a decent amount of virtual CPU cores for the build
process. A reasonable option would be the i3.large instance which comes with a
dedicated NVME SSD.

After connecting to the instance via SSH the necessary tools have to be
installed as shown in the listing below. The listing also shows how to format
and mount the NCME drive that comes with the AWS instance. Now the AOSP
repository of the corresponding Android version can be downloaded onto the SSD
with the help of the repo tool.

    # Install all necessary tools for the build
    sudo dpkg --add-architecture i386
    sudo apt update && sudo apt upgrade
    sudo apt install openjdk-7-jdk gcc-multilib g++ bison git zip
    sudo apt install g++-multilib gperf libxml2-utils make zlib1g-dev:i386
    mkdir ~/bin
    curl http://commondatastorage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
    chmod a+x ~/bin/repo
    export PATH=~/bin:$PATH
    
    # Prepare the SSD
    sudo mkfs.ext4 /dev/nvme0n1 
    sudo mount /dev/nvme0n1 mnt
    chown -R ubuntu:ubuntu mnt/
    mkdir mnt/android
    cd mnt/android/
    
    # Clone the Android repository
    repo init -u https://android.googlesource.com/platform/manifest -b android-6.0.1_r81
    repo sync

Then it is possible to build the Bluetooth stack with all necessary
dependencies. The lunch script can also be invoked without any arguments to
select the build target from an interactive list. The debugging features of the
Bluetooth stack are enabled by setting the preprocessor define
BT_NET_DEBUG=TRUE. The build script is called mma and takes an optional
argument -j to specify the number of CPU cores to use in parallel. It should be
chosen according to the selected AWS instance. The following command sequence
builds just the Bluetooth stack of the AOSP:

    source build/envsetup.sh
    lunch aosp_hammerhead-userdebug
    cd system/bt/
    bdroid_CFLAGS='-DBT_NET_DEBUG=TRUE' mma -j4


Build (Lineage OS)
------------------

To compile the Bluetooth debug library for LineageOS 14.1, the steps are
slightly different than for AOSP:

Follow the build setup steps according to https://wiki.lineageos.org/devices/hammerhead/build
until the Start the build section. Then do:

    cd system/bt/
    bdroid_CFLAGS='-DBT_NET_DEBUG=TRUE' mma -j4

Flex crashes on Ubuntu 18.04 - [workaround](https://stackoverflow.com/questions/49301627/android-7-1-2-armv7):

    export LC_ALL=C


Installation
------------

After the build process is done, the *bluetooth.default.so* shared library can be
found in /home/ubuntu/mnt/android/out/target/product/hammerhead/system/lib/hw/bluetooth.default.so
and pushed onto the smartphone via ADB. To overwrite the existing library on
the Android system partition it must first be remounted in order to make it
writable. It is also important to verify that the new library is actually set
to be executable, otherwise Bluetooth will not work on the device.

    adb push bluetooth.default.so /sdcard/bluetooth.default.so
    adb shell 'su -c "mount -o remount,rw /system"'
    adb shell 'su -c "cp /sdcard/bluetooth.default.so /system/lib/hw/bluetooth.default.so"'
    adb shell 'su -c "chmod 644 /system/lib/hw/bluetooth.default.so"'
    adb shell 'su -c "chown root:root /system/lib/hw/bluetooth.default.so"'

Finally, the *HCI snoop log* feature has to be enabled in the developer settings
of the Android phone.
