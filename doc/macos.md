

macOS Setup
-----------



### 1. Prerequisites
The [unicorn CPU emulator framework](https://github.com/unicorn-engine/unicorn) has to be installed first, preferrably with [Homebrew](https://brew.sh).

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
brew install unicorn
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

### 3. Framework Setup:

#### a) Precompiled
On macOS High Sierra or older, you need to use a precompiled [IOBluetoothExtended.framework](../macos/IOBluetoothExtended.framework.zip) file.
It only runs after installing the *Swift 5 Runtime Support Command Line Tools*, otherwise, the error
message `Library not loaded: @rpath/libswiftCore.dylib` is shown.
Use the following command to unzip the framework we provide.
```
unzip macos/IOBluetoothExtended.framework.zip -d macos
```

#### b) Compile yourself
On macOS Mojave and newer, *Xcode 10.2.1* and up is supported. On these systems, you can build the
framework yourself.

```
open internalblue/macos-framework/IOBluetoothExtended/IOBluetoothExtended.xcodeproj/
```

⌘ + B

### 4. Startup
Now, *InternalBlue* can be executed normally, like shown.
```
python3 -m internalblue.cli
```

If you want to use ARM assembly and disassembly, which is required for some patches and debugging, install *Xcode 10.2.1* and [binutils](https://github.com/Gallopsled/pwntools-binutils).
```
brew install https://github.com/Gallopsled/pwntools-binutils/raw/master/osx/binutils-arm.rb
```

If you do excessive IO such as dumping the ROM and get the message `Failure: creating socket: Too many open
files`, you need to change the `ulimit`.
