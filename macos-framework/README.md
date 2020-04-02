

macOS Setup
-----------

```
brew install unicorn
pip install pwntools
pip install pyobjc
```

On macOS High Sierra or older, you need to use a precompiled [IOBluetoothExtended.framework](IOBluetoothExtended.framework.zip) file.
It only runs after installing the *Swift 5 Runtime Support Command Line Tools*, otherwise, the error
message `Library not loaded: @rpath/libswiftCore.dylib` is shown.

On macOS Mojave and newer, *Xcode 10.2.1* and up is supported. On these systems, you can build the
framework yourself.

```
open internalblue/macos-framework/IOBluetoothExtended/IOBluetoothExtended.xcodeproj/
```

⌘ + B

```
python3 -m internalblue.cli
```

If you want to use ARM assembly and disassembly, which is required for some patches and debugging:

* brew install https://github.com/Gallopsled/pwntools-binutils/raw/master/osx/binutils-arm.rb
* Xcode 10.2.1

If you do excessive IO such as dumping the ROM and get the message `Failure: creating socket: Too many open
files`, you need to change the `ulimit`.