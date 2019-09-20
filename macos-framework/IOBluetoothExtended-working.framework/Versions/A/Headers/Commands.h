//
//  Commands.h
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 06.07.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>
#import "IOBluetoothHostController.h"

#ifndef Commands_h
#define Commands_h

@interface HCIDelegate: NSObject

@property (nonatomic, assign) unsigned short waitingFor;
@property (nonatomic, assign) NSString *hostname;
@property (nonatomic, assign) NSString *inject;
@property (nonatomic, assign) NSString *snoop;

@property (nonatomic, assign) int32_t sock_fd;
@property (nonatomic, assign) int32_t client_fd;

@property (nonatomic, assign) Boolean exit_requested;

+ (void) setWaitingFor:(unsigned short)arg1;
+ (void) setHostname:(NSString *)arg1;

+ (void) setInject:(NSString *)arg1;
+ (void) setSnoop:(NSString *)arg1;

- (void) shutdown;

@end

@interface Commands: NSObject

+ (void) readConnectionAcceptTimeout;
+ (void) readLocalVersionInformation;
+ (void) readBDAddr;

+ (void) sendArbitraryCommand:(long long)arg1;
+ (NSArray *) sendArbitraryCommand4:(uint8_t [])arg1 len:(uint8_t)arg2;

+ (void) setDelegate:(HCIDelegate*)arg1 of:(IOBluetoothHostController*)arg2;

@end

#endif /* Commands_h */
