macOS Setup
-----------

### 1. Prerequisites

*InternalBlue* runs as regular user, no administrator access is required.

Install `homebrew` (see https://brew.sh/) and then use it to install `git` and `python3`.

If you want to use ARM assembly and disassembly, which is required for some patches and debugging, install[binutils](https://github.com/Gallopsled/pwntools-binutils).
```
brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/macos/binutils-arm.rb
```

### 2. Installation

#### a) With Git
Clone *InternalBlue* and install it. Preferrably in a new virtual environment.
```
git clone https://github.com/seemoo-lab/internalblue
cd internalblue

virtualenv -p python3 venv
source venv/bin/activate
pip install --editable ./
pip install pyobjc
```

Without `pyobjc`, you might get an error message that the `IOBluetoothExtended.framework` was not found even
if the folder is correct.

#### b) Without Git
Download *InternalBlue* and install it. Preferrably in a new virtual environment.
```
curl -LJO https://github.com/seemoo-lab/internalblue/archive/master.zip
unzip internalblue-master.zip
cd internalblue-master

virtualenv -p python3 venv
source venv/bin/activate
pip install --editable ./
pip install pyobjc
```

### 3. Framework Setup

#### a) Precompiled
On macOS High Sierra or older, you need to use a precompiled [IOBluetoothExtended.framework](../macos/IOBluetoothExtended.framework.zip) file.
It only runs after installing the *Swift 5 Runtime Support Command Line Tools*, otherwise, the error
message `Library not loaded: @rpath/libswiftCore.dylib` is shown.
Use the following command to unzip the framework we provide.

```
unzip macos/IOBluetoothExtended.framework.zip -d macos
```

Depending on the installation location, if the `IOBluetoothExtended.framework` is still not found, you might need to
adapt the path in `macoscore.py`.


#### b) Compile yourself
On macOS Mojave and newer, *Xcode 10.2.1* and up is supported. On these systems, you can build the
framework yourself.

```
open internalblue/macos/IOBluetoothExtended/IOBluetoothExtended.xcodeproj/
```

⌘ + B

### 4. Startup
Now, *InternalBlue* can be executed normally, like shown.
```
python3 -m internalblue.cli
```
You can also use the shortcut `internalblue`.


### 5. Debugging

You can open `PacketLogger`, which is included in the `Additional Tools for Xcode`, to observe all Bluetooth packets.

If you do excessive IO such as dumping the ROM and get the message `Failure: creating socket: Too many open
files`, you need to change the `ulimit`, i.e., `ulimit -n 1000`.


