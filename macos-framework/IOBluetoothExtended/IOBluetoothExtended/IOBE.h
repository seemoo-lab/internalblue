//
//  IOBE.h
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 19.09.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>

#ifndef IOBE_h
#define IOBE_h

@class HCIDelegate;

@interface IOBE: NSObject {
    IOBluetoothHostController *controller;
    HCIDelegate *delegate;
}

- (void) shutdown;

@end

#endif /* IOBE_h */
