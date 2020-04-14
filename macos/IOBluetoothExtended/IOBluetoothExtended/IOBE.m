//
//  IOBE.m
//  IOBluetoothExtended
//
//  Created by Davide Toldo on 19.09.19.
//  Copyright © 2019 Davide Toldo. All rights reserved.
//

#import "IOBE.h"
#import "HCIDelegate.h"

@implementation IOBE

- (id) initWith:(NSString *)inject and:(NSString*)snoop {
    if (self = [super init]) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            self->controller = IOBluetoothHostController.defaultController;
            self->delegate = [[HCIDelegate alloc] initWith:inject and:snoop];
            self->controller.delegate = self->delegate;
            
            [[NSRunLoop currentRunLoop] run];
        });
    }
    return self;
}

- (void) shutdown {
    [self->delegate shutdown];
}

@end
