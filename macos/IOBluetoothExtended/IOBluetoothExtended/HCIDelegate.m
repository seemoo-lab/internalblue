//
//  Commands.m
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 06.07.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import "HCIDelegate.h"
#import "IOBluetoothExtended/IOBluetoothExtended-Swift.h"

@implementation HCIDelegate

Boolean exit_requested = false;

- (id) initWith:(NSString *)inject and:(NSString*)snoop {
    if (self = [super init]) {
        self.inject = inject;
        self.snoop = snoop;
        self.hostname = @"127.0.0.1";
        [self initServer];
    }
    return self;
}

+ (void) setHostname:(NSString *)hostname {
    self.hostname = hostname;
}

+ (void) setInject:(NSString *)port {
    self.inject = port;
}

+ (void) setSnoop:(NSString *)port {
    self.snoop = port;
}

- (void) shutdown {
    exit_requested = true;
}

@end
