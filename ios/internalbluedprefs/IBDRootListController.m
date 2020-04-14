#include <xpc/xpc.h>

#include "IBDRootListController.h"
#import <Preferences/PSListController.h>
#import <Preferences/PSViewController.h>
#import <Preferences/PSSpecifier.h>
#include "../xpc_protocol.h"

#define PREF_FILE @"/var/mobile/Library/Preferences/com.ttdennis.internalblue-prefs.plist"

@implementation IBDRootListController

xpc_connection_t get_connection() {
    xpc_connection_t connection = xpc_connection_create_mach_service(
            "com.ttdennis.internalblued", NULL, 0);
    // we don't expect any responses anyway
	xpc_connection_set_event_handler(connection, ^(xpc_object_t some_object) { });
	xpc_connection_resume(connection);

    NSLog(@"connection %@", connection);
    return connection;
}

-(bool) should_stop {
    for (PSSpecifier *spec in [self specifiers]) {
        if ([[spec identifier] isEqualToString:@"enabled"]) {
            bool isEnabled = [[self readPreferenceValue:spec] boolValue];
            NSLog(@"Toggle is: %d", isEnabled);
            return !isEnabled;
        }
    }
    return false;
}

- (void)toggle:(NSNotification *)notification {
    // close the number keyboard
    [self.view endEditing:YES];
    // force write the preference file so that the daemon will pick up the correct value
    CFPreferencesSynchronize(CFSTR("com.ttdennis.internalblue-prefs"), kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);

    sleep(1);

    xpc_connection_t connection = get_connection();
    xpc_object_t object = xpc_dictionary_create(NULL, NULL, 0);
   
    if ([self should_stop]){
        xpc_dictionary_set_uint64(object, "message", CMD_STOP_PROXY);
    } else {
        xpc_dictionary_set_uint64(object, "message", CMD_START_PROXY);
    }
    
    xpc_connection_send_message(connection, object);
}

void notify_ns() {
    [[NSNotificationCenter defaultCenter] postNotificationName:@"com.ttdennis.internalblue/toggle" object:nil];
}


- (id) init {
    self = [super init];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(toggle:) 
                                            name:@"com.ttdennis.internalblue/toggle"
                                            object:nil];
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), (__bridge const void *)(self), (CFNotificationCallback)notify_ns, 
            CFSTR("com.ttdennis.internalblue/toggle"), NULL, 0);
            
    return self;
}

- (NSArray *)specifiers {
	if (!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

@end
