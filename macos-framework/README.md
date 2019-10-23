

macOS Setup
-----------

* `brew install unicorn`
* `pip install pwntools`
* `pip install pyobjc`

* `open internalblue/macos-framework/IOBluetoothExtended/IOBluetoothExtended.xcodeproj/`
* ⌘ + B
* `python internalblue/cli.py`

If you want to use ARM assembly and disassembly, which is required for some patches and debugging:

* brew install https://github.com/Gallopsled/pwntools-binutils/raw/master/osx/binutils-arm.rb
* Xcode 10.2.1