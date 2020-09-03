#include <xpc/xpc.h>
#include <pthread.h>
#include <spawn.h>

#include "ios-proxy.h"
#include "xpc_protocol.h"

#define PREF_FILE @"/var/mobile/Library/Preferences/com.ttdennis.internalblue-prefs.plist"

int manual_port = -1;
bool proxy_is_running = false;
pthread_t proxy_thread;

int get_proxy_port() {
    int port = 0;
    if (manual_port != -1) {
        return manual_port;
    }
    
    NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile: PREF_FILE];
    if (prefs) {
        port = [[prefs objectForKey:@"port"] intValue];
    } else {
        NSLog(@"Preference file not found, chosing standard port 1234");
    }

    if (port == 0)
        port = 1234;

    return port;
}

bool proxy_pref_on() {
    bool res = true;
    NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile: PREF_FILE];
    if (prefs) {
        id obj = [prefs objectForKey:@"isEnabled"];
        // no object exists, this means the user never toggled the switch
        // which means the server is on (because it is by default), and we
        // should stop -> return true
        if (!obj) {
            return true;
        }
        res = [obj boolValue];
    } else {
        NSLog(@"Preference file not found, chosing standard value true");
    }

    return res;
}

void *proxy_fn() {
    int port = get_proxy_port();
    int server_fd, client_fd;

    while (proxy_is_running) {
        server_fd = create_server(port);
        if (server_fd < 0) {
            NSLog(@"Unable to create proxy server: %s", strerror(errno));
            break;
        }
        NSLog(@"Created proxy server, waiting for connection");

        client_fd = wait_for_connection(server_fd);
        if (client_fd < 0) {
            NSLog(@"Unable to establish connection: %s", strerror(errno));
            close(server_fd);
        }
        NSLog(@"Connection established, connecting PCIe transports");
        my_connection_t *my_conn;

        my_conn = connect_bt_pcie();
        NSLog(@"PCIe transports created, starting proxy...");
        proxy_bt_pcie(client_fd, my_conn);

        close(client_fd);
        close(server_fd);
        // Maybe add a function that Frees everything
    }

    return NULL;
}

void start_proxy() {
    if (proxy_is_running) {
        NSLog(@"Cannot start proxy, it is already running");
    } else {
        pthread_create(&proxy_thread, NULL, &proxy_fn, NULL);
        proxy_is_running = true;
    }
}

void stop_proxy() {
    if (proxy_is_running) {
        pthread_kill(proxy_thread, SIGKILL);
        proxy_is_running = false;
    } else {
        NSLog(@"Cannot stop proxy, it is not running");
    }
}

void _ib_xpc_recv_handler(xpc_object_t object) {
    uint64_t opcode = xpc_dictionary_get_uint64(object, "message");
    if ((void*)opcode == NULL) {
        NSLog(@"Received invalid message.");
        return;
    }
    NSLog(@"Got message with opcode %llu", opcode);

    switch(opcode) {
        case CMD_START_PROXY:
            start_proxy();
            break;
        case CMD_STOP_PROXY:
            stop_proxy();
            break;
    }
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
        if (argc > 1) {
            int port = atoi(argv[1]);
            NSLog(@"Hi, looks like you manually started internalblued on port %d", port);
            if (proxy_pref_on()) {
                int _configured_port = get_proxy_port();
                NSLog(@"internalblued is already running on port %d. Please turn it off in the iPhone's preferences first, before launching it manually.", _configured_port);
                exit(-1);
            }
            manual_port = port;
            start_proxy();
            [[NSRunLoop currentRunLoop] run];
        } else {
            // Start the proxy if pref allows us to
            if (proxy_pref_on()) {
                NSLog(@"Starting proxy because it is enabled.");
                start_proxy();
            }

            // Attempt to create the server, exit if this fails
            xpc_connection_t connection = xpc_connection_create_mach_service("com.ttdennis.internalblued", NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
            if (!connection) {
                NSLog(@"Failed to create XPC server. Exiting.");
                return 0;
            }

            // Configure event handler
            xpc_connection_set_event_handler(connection, ^(xpc_object_t object) {
                xpc_type_t type = xpc_get_type(object);
                if (type == XPC_TYPE_CONNECTION) {
                    NSLog(@"XPC server received incoming connection: %s", xpc_copy_description(object));

                    xpc_connection_set_event_handler(object, ^(xpc_object_t some_object) {
                        NSLog(@"XPC connection received object: %s", xpc_copy_description(some_object));
                        _ib_xpc_recv_handler(some_object);
                    });
                    xpc_connection_resume(object);
                } else if (type == XPC_TYPE_ERROR) {
                    NSLog(@"XPC server error: %s", xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION));
                } else {
                    NSLog(@"XPC server received unknown object: %s", xpc_copy_description(object));
                }
            });

            xpc_connection_resume(connection);
            [[NSRunLoop currentRunLoop] run];
        }
		return 0;
	}
}
