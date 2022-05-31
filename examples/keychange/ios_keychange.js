/*
 Keychange

 The Bluetooth chip cannot save its key internally, so it asks iOS with
 the according HCI command, which we exchange.

  Usage:

    * Attach to existing daemon
        frida -U bluetoothd --no-pause -l ios_keychange.js
*/

var swap_key = false;  // actually swap the key (otherwise just prints the key)
var debug = false;    // enable/disable printing raw packets


var base = Module.getBaseAddress('bluetoothd');

// *** SELECT YOUR IOS VERSION HERE ***
// Functions contain function name strings, easy to determine.
var OI_HCIIfc_DataReceived = base.add(0xee5a4);  // iOS 14.1, iPhone 12
// var OI_HCIIfc_DataReceived = base.add(0xed9f8);  // iOS 14.8, iPhone 8
// var OI_HCIIfc_DataReceived = base.add(0xed0b8);  // iOS 14.4, iPhone 8
// var OI_HCIIfc_DataReceived = base.add(0xee9f0);  // iOS 14.3, iPhone 8 (18C66)
// var OI_HCIIfc_DataReceived = base.add(0x108e04);  // iOS 13.5, iPhone SE2

var OI_HciIfc_CopyPayload = base.add(0xe3d7c);  // iOS 14.1, iPhone 12
// var OI_HciIfc_CopyPayload = base.add(0xe3764);  // iOS 14.8, iPhone 8
// var OI_HciIfc_CopyPayload = base.add(0xe2ddc);  // iOS 14.4, iPhone 8
// var OI_HciIfc_CopyPayload = base.add(0xFE690);  // iOS 13.5, iPhone SE2
// var OI_HciIfc_CopyPayload = base.add(0xee9f0);  // iOS 14.3, iPhone 8 (18C66)

var HCIIfc_src_ptr = base.add(0x671388); // iOS 14.1, iPhone 12
// var HCIIfc_src_ptr = base.add(0x688518); // iOS 14.8, iPhone 8
// var HCIIfc_src_ptr = base.add(0x654318); // iOS 14.4, iPhone 8
// var HCIIfc_src_ptr = base.add(0x6118A0); // iOS 13.5, iPhone SE2


// Helper function to print hex
function print_hex(byte_array) {
	var bytes_string = "";
	for (var i = 0; i < byte_array.length; i+=1) {
        bytes_string += ("00" + byte_array[i].toString(16)).substr(-2);
    }
    console.log('\t' + bytes_string);
}

// *** Receiving direction *** (Chip -> iOS)
// OI_HCIIfc_DataReceived gets all packet types. It then calls
// HCI/SCO/ACL in the next step, and with one function in between
// ends up in OI_HCIIfc_AclPacketReceived (aka acl_recv).
// We don't necessarily need this but at least we can print if a
// key was requested.

Interceptor.attach(OI_HCIIfc_DataReceived, {
    onEnter: function(args) {

        var h4t = parseInt(this.context.x0);  // ACL/SCO/HCI
        var acl = this.context.x1;
        var len = parseInt(this.context.x2);
        if (debug) {
            console.log("OI_HCIIfc_DataReceived" + ", type " + h4t + ", len " + len);
            console.log(acl.readByteArray(len));
        }

        // Uncomment this to filter for a specific type:
        //  HCI: 0x01 (command, invalid in this direction)
        //  ACL: 0x02
        //  SCO: 0x03
        //  HCI: 0x04 (events + BLE data, this is valid)
        //  DIAG: 0x07 (should be disabled here)

        //if (h4t == 4) {
        //}
    }
});

// *** Sending direction *** (iOS -> Chip)
// We need to exchange the original key here.
var OI_HciIfc_CopyPayload_dst = 0;
Interceptor.attach(OI_HciIfc_CopyPayload, {
    onEnter: function(args) {
        // save the payload pointer argument
        OI_HciIfc_CopyPayload_dst = this.context.x0;
    },
    onLeave: function(args) {

        // Intercept all data from the global struct.
        // OI_HciIfc_CopyPayload doesn't intercept the H4 type but we
        // might want to distinguish between ACL/HCI/... for fuzzing.
        var h4t = HCIIfc_src_ptr.add(0x10).readU8();
        var hnd = HCIIfc_src_ptr.add(0x18).readU16();
        var len = HCIIfc_src_ptr.add(0x1c).readU16();

        // This is the data. Depending on the H4 type, it needs to
        // be reassembled differently (different length positions etc.)
        var data = OI_HciIfc_CopyPayload_dst.readByteArray(len);

        if (debug) {
            console.log("OI_HciIfc_CopyPayload, type " + h4t.toString(16) + ", cmd/hnd " + hnd.toString(16) + ", len " + len);
            console.log(data);
        }

        if (h4t == 1 && hnd == 0x40b) {
            console.log("HCI_Link_Key_Request_Reply");

            console.log("  * Intercepted address and key:")
            data = new Uint8Array(data);  // transform to normal array
            var bd_addr =  data.slice(0,6);
            var link_key = data.slice(6);
            print_hex(bd_addr);
            print_hex(link_key);

            if (swap_key) {
                console.log("  ! Replacing key with an invalid one.")
                OI_HciIfc_CopyPayload_dst.add(6).writeByteArray([0x13, 0x37, 0x42, 0x23, 0xde, 0xad, 0xbe, 0xef]); // just flipping a few bytes
            }
        }

    }
});
