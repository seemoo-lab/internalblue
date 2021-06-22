/*
 Keychange

 The Bluetooth chip cannot save its key internally, so it asks Android with
 the according HCI command, which we exchange.

  Usage:

    * Attach to existing daemon
        frida -U com.android.bluetooth --no-pause -l android_keychange.js
*/

var swap_key = true;  // actually swap the key (otherwise just prints the key)
var debug = false;    // enable/disable printing raw packets

// Addresses for Samsung Galaxy Note 20 5G January 2021
var base = Module.getBaseAddress('libbluetooth.so');
//var filter_incoming_event = base.add(0x2efcb4);  // from hci_layer.cc
var transmit_command = base.add(0x2f201c);  // from hci_layer.cc


/*
 Helper functions
*/

function print_hex(byte_array) {
	var bytes_string = "";
	for (var i = 0; i < byte_array.length; i+=1) {
        bytes_string += ("00" + byte_array[i].toString(16)).substr(-2);
    }
    console.log('\t' + bytes_string);
}


function print_backtrace(ctx) {
        console.log('Backtrace:\n' +
        Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
}

/* *** Receiving direction ***
Interceptor.attach(filter_incoming_event, {
    onEnter: function(args) {
        if (debug) {
            console.log("filter_incoming_event");
        }
    }
});
*/


/*

We exchange the original key in the host's key response.


static void transmit_command(BT_HDR* command,
                             command_complete_cb complete_callback,
                             command_status_cb status_callback, void* context)


typedef struct {
  uint16_t event;
  uint16_t len;
  uint16_t offset;
  uint16_t layer_specific;
  uint8_t data[];
} BT_HDR;
*/
Interceptor.attach(transmit_command, {
    onEnter: function(args) {

        var BT_HDR = this.context.x0;

        if (debug) {
            console.log("transmit_command");
            var event = BT_HDR.readU16();
            var len = BT_HDR.add(2).readU16();
            var offset = BT_HDR.add(4).readU16();
            var layer_specific = BT_HDR.add(6).readU16();

            // I think the event is always BT_EVT_TO_LM_HCI_CMD = 0x2000
            console.log("event: " + event);
            console.log("len:   " + len);
            console.log("off:   " + offset);
            console.log("spec:  " + layer_specific);

            // When setting the name:
            // 00000000  13 0c f8 46 6f 6f 66 6f 6e 65 00 00 00 00 00 00  ...Foofone......
            // Write_Local_Name = 0xC13
            console.log(BT_HDR.add(8).readByteArray(len));
        }


        var hci_cmd = BT_HDR.add(8).readU16();

        if (hci_cmd == 0x40b) {
            console.log("HCI_Link_Key_Request_Reply");

            console.log("  * Intercepted address and key:");
            var data = new Uint8Array(BT_HDR.add(11).readByteArray(6+16));  // transform to normal array
            var bd_addr =  data.slice(0,6);
            var link_key = data.slice(6);
            print_hex(bd_addr);
            print_hex(link_key);

            if (swap_key) {
                console.log("  ! Replacing key with an invalid one.");
                BT_HDR.add(11+6).writeByteArray([0x13, 0x37, 0x42, 0x23, 0xde, 0xad, 0xbe, 0xef]); // just flipping a few bytes
            }
        }

        // BLE with SMP on Mi Band 2 uses this

        if (hci_cmd == 0x2019) {
            console.log("LE_Enable_Encryption");

            console.log("  * Intercepted handle and key:");
            var hnd = new Uint8Array(BT_HDR.add(11).readByteArray(2));  // transform to normal array
            var link_key = new Uint8Array(BT_HDR.add(23).readByteArray(16));
            print_hex(hnd);
            print_hex(link_key);

             if (swap_key) {
                console.log("  ! Replacing key with an invalid one.");
                BT_HDR.add(23).writeByteArray([0x13, 0x37, 0x42, 0x23, 0xde, 0xad, 0xbe, 0xef]); // just flipping a few bytes
            }
        }

        // TODO Other BLE variant - didn't test it on any device yet

        if (hci_cmd == 0x201a) {
            console.log("LE_Long_Term_Key_Request_Reply");

            console.log("  * Intercepted handle and key:");
            var data = new Uint8Array(BT_HDR.add(11).readByteArray(2+16));  // transform to normal array
            var hnd =  data.slice(0,2);
            var link_key = data.slice(2);
            print_hex(hnd);
            print_hex(link_key);

             if (swap_key) {
                console.log("  ! Replacing key with an invalid one.");
                BT_HDR.add(11+2).writeByteArray([0x13, 0x37, 0x42, 0x23, 0xde, 0xad, 0xbe, 0xef]); // just flipping a few bytes
            }
        }

    }
});
