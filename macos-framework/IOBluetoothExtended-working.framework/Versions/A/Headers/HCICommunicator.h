//
//  HCICommunicator.h
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 19.09.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifndef HCICommunicator_h
#define HCICommunicator_h

@interface HCICommunicator: NSObject

+ (NSArray *) sendArbitraryCommand4:(uint8_t [])arg1 len:(uint8_t)arg2;

@end

#endif /* HCICommunicator_h */
