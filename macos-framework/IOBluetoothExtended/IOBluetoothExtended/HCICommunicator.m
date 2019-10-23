//
//  HCICommunicator.m
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 19.09.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import "HCICommunicator.h"
#import "IOBluetoothExtended.h"
#import <IOBluetoothHostController.h>

@implementation HCICommunicator

+ (NSArray *)sendArbitraryCommand4:(uint8_t [])arg1 len:(uint8_t)arg2 {
    NSData *data = [NSData dataWithBytes:arg1 length:arg2];
    uint8_t *command = calloc(arg2, sizeof(uint8_t));
    memcpy(command, [data bytes], arg2);
    
    BluetoothHCIRequestID request = 0;
    static uint8_t* output[255];
    size_t outputSize = sizeof(output);
    
    int error = BluetoothHCIRequestCreate(&request, 1000, nil, 0);
    if (error) {
        BluetoothHCIRequestDelete(request);
        printf("Couldn't create error: %08x\n", error);
    }
    
    size_t commandSize = 3;
    if (arg2 > 2) {
        commandSize += command[2];
    }
    error = _BluetoothHCISendRawCommand(request, command, commandSize, &output, outputSize);
    
    if (error) {
        BluetoothHCIRequestDelete(request);
        printf("Send HCI command Error: %08x\n", error);
    }
    
    sleep(0x1);
    BluetoothHCIRequestDelete(request);
    
    uint8_t *result = calloc(255, sizeof(uint8_t));
    memcpy(result, output, 255);
    
    NSMutableArray *nsarr = [[NSMutableArray alloc] init];
    for (int i = 0; i < 255; i++) {
        [nsarr addObject:[NSNumber numberWithUnsignedChar:result[i]]];
    }
    
    return nsarr;
}

int _BluetoothHCISendRawCommand(BluetoothHCIRequestID request,
                                void *commandData,
                                size_t commmandSize,
                                void *returnParameter,
                                size_t returnParameterSize) {
    
    int errorCode = 0;
    
    struct IOBluetoothHCIDispatchParams call;
    size_t size = 0x74;
    memset(&call, 0x0, size);
    
    if ((commandData != 0x0) && (commmandSize > 0x0)) {
        
        // IOBluetoothHostController::
        // SendRawHCICommand(unsigned int, char*, unsigned int, unsigned char*, unsigned int)
        call.args[0] = (uintptr_t)&request;
        call.args[1] = (uintptr_t)commandData;
        call.args[2] = (uintptr_t)&commmandSize;
        call.sizes[0] = sizeof(uint32);
        call.sizes[1] = commmandSize;
        call.sizes[2] = sizeof(uintptr_t);
        call.index = 0x000060c000000062;
        
        errorCode = BluetoothHCIDispatchUserClientRoutine(&call, returnParameter, &returnParameterSize);
    }
    else {
        errorCode = 0xe00002c2;
    }
    
    return errorCode;
}

@end
