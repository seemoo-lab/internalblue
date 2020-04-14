//
//  HCIDelegate.h
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 06.07.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>

#ifndef HCIDelegate_h
#define HCIDelegate_h

@interface HCIDelegate: NSObject

@property (nonatomic, assign) NSString *hostname;
@property (nonatomic, assign) NSString *inject;
@property (nonatomic, assign) NSString *snoop;

@property (nonatomic, assign) int32_t sock_fd;
@property (nonatomic, assign) int32_t client_fd;

@property (nonatomic, assign) Boolean exit_requested;

- (id) initWith:(NSString *)inject and:(NSString*)snoop;

+ (void) setHostname:(NSString *)arg1;

+ (void) setInject:(NSString *)arg1;
+ (void) setSnoop:(NSString *)arg1;

- (void) shutdown;

@end

#endif /* HCIDelegate_h */
