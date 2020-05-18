# MagicPairing PoCs

This folder contains the proof-of-concepts belonging to our WiSec paper 
[MagicPairing: Apple's Take on Securing Bluetooth Peripherals](https://arxiv.org/abs/2005.07255).

Run the `mp_pocs.py` script to try the PoCs. The script will interactively ask
for the required information for each of the PoCs. It assumes a connected iOS
device running InternalBlue. This can be changes by adopting the core to the
desired one (i.e. for macOS `internalblue = macOSCore()`).

For more information on the individual bugs, please refer to our [paper](https://arxiv.org/abs/2005.07255).
