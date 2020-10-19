//
//  ios-proxy.m
//  ios-proxy
//
//  Copyright © 2019 ttdennis. All rights reserved.
//

#include "ios-proxy.h"

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <unistd.h>
#include <termios.h>

#include <dlfcn.h>
#include <sys/poll.h>

void *AppleConvergedTransport_handle;
void (*AppleConvergedTransportInitParameters)(int64_t[11]);
int (*AppleConvergedTransportCreate)(int64_t[11], uint64_t*);
int (*AppleConvergedTransportWrite)(uint64_t,char*, uint64_t, uint64_t*, uint64_t, void*);
int (*AppleConvergedTransportRead)(uint64_t,char*, uint64_t, uint64_t*, uint64_t, void*);
void (*AppleConvergedTransportFree)(uint64_t);
dispatch_queue_attr_t qos;
dispatch_queue_t recordingQueue;

void load_AppleConvergedTransport() {
    static int guard = 0; // poor mans dispatch_once?
    if (guard >= 1) return;
    guard++;
    AppleConvergedTransport_handle = dlopen("/usr/lib/AppleConvergedTransport.dylib", RTLD_LOCAL);
    AppleConvergedTransportInitParameters = dlsym(AppleConvergedTransport_handle, "AppleConvergedTransportInitParameters");
    AppleConvergedTransportCreate = dlsym(AppleConvergedTransport_handle, "AppleConvergedTransportCreate");
    AppleConvergedTransportWrite = dlsym(AppleConvergedTransport_handle, "AppleConvergedTransportWrite");
    AppleConvergedTransportRead = dlsym(AppleConvergedTransport_handle, "AppleConvergedTransportRead");
    AppleConvergedTransportFree = dlsym(AppleConvergedTransport_handle, "AppleConvergedTransportFree");
    //If you want to use an event block Reader: Add Queue For Reading here
    //Then:  Register Event Block Queue
    qos = dispatch_queue_attr_make_with_qos_class(0,0x15,0);
    recordingQueue = dispatch_queue_create("com.internalblue.actbt.queue", qos);
}

int connect_bti_transport(my_connection_t * my_conn) {
    //NSLog(@"ios-proxy.m:connect_bti_transport -> Starting");
    int64_t pciparams[11];
    AppleConvergedTransportInitParameters(pciparams);
    pciparams[0] = 1; //BTI
    pciparams[1] = (int64_t)recordingQueue;// dispatchQ
    //pciparams[2] = (int64_t)&_NSConcreteStackBlock; // Maybe fix this?
    void (^myBlock)() = ^(){NSLog(@"block called");};
    pciparams[2] = (int64_t)&myBlock;
    pciparams[3] = 1000; 
    pciparams[4] = 0;
    //NSLog(@"ios-proxy.m:connect_bti_transport -> Returning");
    return AppleConvergedTransportCreate(pciparams, &my_conn->bti_transport); // THE PROBLEM IS IN HERE
}

int connect_hci_transport(my_connection_t * my_conn) {
    //NSLog(@"ios-proxy.m:connect_hci_transport -> Starting");
    int64_t pciparams[11];
    AppleConvergedTransportInitParameters(pciparams);
    //dispatch_queue_attr_t qos = dispatch_queue_attr_make_with_qos_class(0,0x15,0);
    //dispatch_queue_t rQueue = dispatch_queue_create("com.internalblue.actbt.hci", qos);
    pciparams[0] = 2; //HCI
    //pciparams[1] = (int64_t)rQueue;
    pciparams[1] = (int64_t)recordingQueue;// dispatchQ
    void (^myBlock)() = ^(){NSLog(@"block called");};
    pciparams[2] = (int64_t)&myBlock;
    pciparams[3] = 1000;
    pciparams[4] = 8;
    //pciparams[4] = 12;
    //pciparams[10] = 25;
    //NSLog(@"ios-proxy.m:connect_hci_transport -> Returning");
    return AppleConvergedTransportCreate(pciparams, &my_conn->hci_transport); // returns 1 on success
}

int connect_acl_transport(my_connection_t * my_conn) {
    //NSLog(@"ios-proxy.m:connect_acl_transport -> Starting");
    int64_t pciparams[11];
    AppleConvergedTransportInitParameters(pciparams);
    pciparams[0] = 3; //ACL
    pciparams[1] = 0;
    pciparams[1] = (int64_t)recordingQueue;// dispatchQ
    void (^myBlock)() = ^(){NSLog(@"block called");};
    pciparams[2] = (int64_t)&myBlock;
    pciparams[3] = 1000;
    pciparams[4] = 4;
    pciparams[10] = 33;
    //NSLog(@"ios-proxy.m:connect_acl_transport -> Returning");
    return AppleConvergedTransportCreate(pciparams, &my_conn->acl_transport); // returns 1 on success
}

int connect_sco_transport(my_connection_t * my_conn) {
    //NSLog(@"ios-proxy.m:connect_sco_transport -> Starting");
    int64_t pciparams[11];
    AppleConvergedTransportInitParameters(pciparams);
    pciparams[0] = 4; //SCO
    pciparams[1] = 0;
    pciparams[1] = (int64_t)recordingQueue;// dispatchQ
    //pciparams[2] = (int64_t)&_NSConcreteStackBlock;
    void (^myBlock)() = ^(){NSLog(@"block called");};
    pciparams[2] = (int64_t)&myBlock;
    pciparams[3] = 1000;
    pciparams[4] = 4;
    pciparams[10] = 33;
    //NSLog(@"ios-proxy.m:connect_sco_transport -> Returning");
    return AppleConvergedTransportCreate(pciparams, &my_conn->sco_transport); // returns 1 on success
}

my_connection_t *  connect_bt_pcie() {
    //NSLog(@"ios-proxy.m:connect_bt_pcie -> Entered");
    // This function will create 4 transports on PCIe, and return them in a struct.
    load_AppleConvergedTransport();
    NSLog(@"ios-proxy.m:connect_bt_pcie -> AppleConvergedTransport.dylib Loaded");
    my_connection_t *my_connection = malloc(sizeof(my_connection_t));
    my_connection->bti_transport = 0;
    my_connection->hci_transport = 0;
    my_connection->acl_transport = 0;
    my_connection->sco_transport = 0;
    //NSLog(@"ios-proxy.m:connect_bt_pcie -> Starting transport initialization");
    if (!connect_bti_transport(my_connection)) // should return 1 on success
        NSLog(@"InternalBlue: PCIe Error creating BTI Transport");
    if (!connect_hci_transport(my_connection))
        NSLog(@"InternalBlue: PCIe Error creating HCI Transport");
    if (!connect_acl_transport(my_connection))
        NSLog(@"InternalBlue: PCIe Error creating ACL Transport");
    if (!connect_sco_transport(my_connection))
        NSLog(@"InternalBlue: PCIe Error creating SCO Transport");
    NSLog(@"Transports Initialized:");
    NSLog(@"BTI: %u", (unsigned int) my_connection->bti_transport);
    NSLog(@"HCI: %u", (unsigned int) my_connection->hci_transport);
    NSLog(@"ACL: %u", (unsigned int) my_connection->acl_transport);
    NSLog(@"SCO: %u", (unsigned int) my_connection->sco_transport);
    if (!(my_connection->bti_transport||my_connection->hci_transport||my_connection->acl_transport||my_connection->sco_transport))
        NSLog(@"ERROR: All Transports Failed! Did you forget to turn Bluetooth OFF?");
    return my_connection;
}

void proxy_bt_pcie(int client, my_connection_t * my_conn) {
    //NSLog(@"Allocating Buffers for Proxy Data");
    // this function establishes the relay connection between the transports(bt chip) and the client socket
    // only one fd and a ?
    char *client_buf, *bti_buf, *hci_buf, *acl_buf, *sco_buf; // buffers for incoming data
	
	client_buf = malloc(0x2000);
	bti_buf = malloc(0x2000);
	hci_buf = malloc(0x2000);
	acl_buf = malloc(0x2000);
	sco_buf = malloc(0x2000);
    int ret;
    uint64_t x = 0;
    int check_hci_event = 0;
    
    struct pollfd pfds[1];

    NSLog(@"Starting Proxy Loop");
    while(1){
        pfds[0].fd = client;
        pfds[0].events = POLLIN;
        poll(pfds, 1, 100);
        if(pfds[0].revents & POLLIN) {
            ret = read(pfds[0].fd, client_buf, 4096);
            //NSLog(@"Read Data from client. Size: %u", ret);
            
            if (!ret) {
                // This means that the client probably closed the connection 
                NSLog(@"!!! Client read error");
                NSLog(@"Freeing Transports!");
                AppleConvergedTransportFree(my_conn->bti_transport);
                AppleConvergedTransportFree(my_conn->hci_transport);
                AppleConvergedTransportFree(my_conn->acl_transport);
                AppleConvergedTransportFree(my_conn->sco_transport);
                return;
            }
            //send stuff to bt
            //NSLog(@"Sending Data to BT Chip");
            //NSLog(@"H4 Message Type: 0x%x", ((char *)client_buf)[0]);
            switch(((char*)client_buf)[0]) {
                case 1:
                    ret = AppleConvergedTransportWrite(my_conn->hci_transport, client_buf+1, ret-1, &x, -1, 0); //+1, because we strip the H4 tag
                    check_hci_event = 1;
                    break;
                case 2:
                    ret = AppleConvergedTransportWrite(my_conn->acl_transport, client_buf+1, ret-1, &x, -1, 0);
                    break;
                case 3:
                    ret = AppleConvergedTransportWrite(my_conn->sco_transport, client_buf+1, ret-1, &x, -1, 0);
                    break;
                case 4:
                    ret = AppleConvergedTransportWrite(my_conn->hci_transport, client_buf+1, ret-1, &x, -1, 0);
                    break;
                case 7:
                    if (my_conn->bti_transport){
                        //NSLog(@"sending to bti");
                        ret = AppleConvergedTransportWrite(my_conn->bti_transport, client_buf+1, ret-1, &x, -1, 0);}
                    break;
            }
        }
        //NSLog(@"+ Done sending data to chip");
        // HCI
        if (check_hci_event){
            ret = 0;
            ret = AppleConvergedTransportRead(my_conn->hci_transport, hci_buf+1, 0x102, &x, -1, 0); // if first byte is not 0xe, do another read for more data
            if (hci_buf[1] == (char) 0xe)
                check_hci_event = 0;
            *hci_buf = (char)4; // 1 or 4? (Command or Event)
            NSLog(@"ACTRead (HCI) Returned %u", ret);
            NSLog(@"ATCRead (HCI) to x: %u", (unsigned int)x);
            if (ret != 0) {
                write(pfds[0].fd, hci_buf, x+1);
            }
        }
        //ACL
        ret = 0;
        ret = AppleConvergedTransportRead(my_conn->acl_transport, acl_buf+1, 0x102, &x, -1, 0); // if first byte is not 0xe, do another read for more data
        *acl_buf = (char)2;
        if (ret != 0) {
        NSLog(@"ACTRead (ACL) Returned %u", ret);
        NSLog(@"ATCRead (ACL) to x: %u", (unsigned int)x);}
        if (ret != 0) {
            write(pfds[0].fd, acl_buf, x+1);
        }
        //SCO
        ret = 0;
        ret = AppleConvergedTransportRead(my_conn->sco_transport, sco_buf+1, 0x102, &x, -1, 0); // if first byte is not 0xe, do another read for more data
        *sco_buf = (char)3;
        if (ret != 0) {
        NSLog(@"ACTRead (SCO) Returned %u", ret);
        NSLog(@"ATCRead (SCO) to x: %u", (unsigned int)x);}
        if (ret != 0) {
            write(pfds[0].fd, sco_buf, x+1);
        }
        //BTI
        ret = 0;
        ret = AppleConvergedTransportRead(my_conn->bti_transport, bti_buf+1, 0x102, &x, -1, 0); // if first byte is not 0xe, do another read for more data
        *bti_buf = (char)7;
        if (ret != 0) {
        NSLog(@"ACTRead (BTI) Returned %u", ret);
        NSLog(@"ATCRead (BTI) to x: %u", (unsigned int)x);
        }
        if (ret != 0) {
            write(pfds[0].fd, bti_buf, x+1);
        }
    }
}

int create_server(int port) {
	int server_fd;
	struct sockaddr_in server;
	int on = 1;
	int addrlen;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		NSLog(@"[!] Unable to create server socket\n");
		return -1;
	}
	
	addrlen = sizeof(server);
	memset(&server, '\0', addrlen);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(port);
	
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, 4);
	if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		NSLog(@"[!] Error binding socket\n");
		return -1;
	}
	
	if (listen(server_fd, 5) < 0) {
		NSLog(@"[!] Failed listening on port %d,  Error: %s\n", port, strerror(errno));
		return -1;
	}
	
	NSLog(@"[*] Listening on port %d\n", port);
	
	return server_fd;
}

int wait_for_connection(int server_fd) {
	int client_fd;
	socklen_t len;
	struct sockaddr_in client;
	
	len = sizeof(struct sockaddr_in);
	client_fd = accept(server_fd, (struct sockaddr *)&client, (socklen_t *)&len);
	
	if (client_fd < 0) {
		NSLog(@"[!] Accepting connection failed\n");
		return -1;
	}
	
	return client_fd;
}
