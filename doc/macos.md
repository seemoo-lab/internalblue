Prerequisites
-------------

*InternalBlue* runs as regular user, no administrator access is required.

Install `homebrew` (see https://brew.sh/) and then use it to install `python3`, `cmake`, and optionally `git`.

Hardware and OS
---------------

*InternalBlue* support is the best on *macOS Catalina* with a *BCM20703A2* chip. Symbols for this particular chip
are in our [Polypyus](https://github.com/seemoo-lab/polypyus) repo, and on *Catalina*, the HCI command for writing
to RAM still works.

Basic operation and Bluetooth hacking is supported on anything from *macOS High Sierra* to *macOS Big Sur* as long
as it is a Broadcom chip :)

Installation
-----------

#### [1] Get files
Get *InternalBlue*, either by cloning with `git`
```sh
git clone https://github.com/seemoo-lab/internalblue
cd internalblue
```
or downloading from GitHub.
```sh
curl -LJO https://github.com/seemoo-lab/internalblue/archive/master.zip
unzip internalblue-master.zip
cd internalblue-master
```

#### [2] New virtual environment.
```sh
pip3 install virtualenv
virtualenv -p python3 venv
source venv/bin/activate
```

#### [3] Install
Now you have to choose whether you want to install the requirements for (dis)assembly,
which can not only take a long time on low-power devices but you also might not need
the features that require these dependencies.

#### [3a] Install Without binutils
If you don't need ARM assembly and disassembly, just specify that you need the macOS-specific dependencies:
```sh
pip install -e .\[macoscore\]
```

#### [3b] Install With binutils
If you want to use ARM assembly and disassembly, which is required for some patches and debugging, install [binutils](https://github.com/Gallopsled/pwntools-binutils).
```sh
brew install wget
wget https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/macos/binutils-arm.rb
brew install binutils-arm.rb
```
Also add the `binutils` requirement so that `pip install` looks like this:
```sh
pip install -e .\[macoscore,binutils\]
``` 

Framework Setup
-----------
#### [a] Precompiled
On macOS High Sierra or older, you need to use a precompiled [IOBluetoothExtended.framework](../macos/IOBluetoothExtended.framework.zip) file.
It only runs after installing the *Swift 5 Runtime Support Command Line Tools*, otherwise, the error
message `Library not loaded: @rpath/libswiftCore.dylib` is shown.
Use the following command to unzip the framework we provide.

```
unzip macos/IOBluetoothExtended.framework.zip -d macos
```

Depending on the installation location, if the `IOBluetoothExtended.framework` is still not found, you might need to
adapt the path in `macoscore.py`.


#### [b] Compile yourself
On macOS Mojave and newer, *Xcode 10.2.1* and up is supported. On these systems, you can build the
framework yourself.

```
open internalblue/macos/IOBluetoothExtended/IOBluetoothExtended.xcodeproj/
```

⌘ + B

Startup
-----------
Now, *InternalBlue* can be executed normally, like shown.
```
python3 -m internalblue.cli
```
You can also use the shortcut `internalblue`.


Debugging
-----------
You can open `PacketLogger`, which is included in the `Additional Tools for Xcode`, to observe all Bluetooth packets.

If you do excessive IO such as dumping the ROM and get the message `Failure: creating socket: Too many open
files`, you need to change the `ulimit`, i.e., `ulimit -n 1000`.


macOS Big Sur
-------------
*InternalBlue* also works on macOS Big Sur! Note that the `writemem` command is blocked. Moreover, to get it working,
you might need to downgrade `pwntools`, i.e., version `4.0.1` seems to work.

