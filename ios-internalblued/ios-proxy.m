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

int connect_bt_device() {
	int socket_fd = socket(32, 1, 2);
	int error = 0;
	int ret = 0;
	
	struct sockaddr sock_addr;
	struct termios term;
	
	if (socket_fd == 0) {
		NSLog(@"[!] Unable to get Bluetooth socket\n");
		return -1;
	}
	
	ctl_info_t *ctl_inf = malloc(sizeof(ctl_info_t));
    ctl_inf->ctl_id = 0;
	strcpy(ctl_inf->ctl_name, "com.apple.uart.bluetooth");
	if ((error = ioctl(socket_fd, CTLIOCGINFO, ctl_inf))) {
		NSLog(@"[!] ioctl(CTLIOCGINFO) = %d - errno: %d\n", error, errno);
		NSLog(@"[!] error: %s\n", strerror(errno));
		return -1;
	}
	
	*(int *)&sock_addr.sa_len = 0x22020;
	*(int *)&sock_addr.sa_data[2] = ctl_inf->ctl_id;
	ret = connect(socket_fd, &sock_addr, 0x20);
	if (ret != 0) {
		NSLog(@"[!] connect() = %d - errno: %d\n", ret, errno);
		NSLog(@"[!] error: %s\n", strerror(errno));
		return -1;
	}
	
	NSLog(@"[*] Connected to Bluetooth chip H4 socket\n");
	
	socklen_t len = 72;
	
	ret = getsockopt(socket_fd, 2, TIOCGETA, &term, &len);
	if (ret != 0) {
		NSLog(@"[!] getsockopt(TIOCGETA) = %d - errno: %d\n", ret, errno);
		NSLog(@"[!] error: %s\n", strerror(errno));
		return -1;
	}
	
	cfmakeraw(&term);
	ret = cfsetspeed(&term, 3000000);
	if (ret != 0) {
		NSLog(@"[!] cfsetspeed() = %d - errno: %d\n", ret, errno);
		NSLog(@"[!] error: %s\n", strerror(errno));
		return -1;
	}
	
	term.c_iflag |= 4;
	term.c_cflag = 232192;
	ret = setsockopt(socket_fd, 2, TIOCSETA, &term, 0x48);
	if (ret != 0) {
		NSLog(@"[!] setsockopt() = %d - errno: %d\n", ret, errno);
		NSLog(@"[!] error: %s\n", strerror(errno));
		return -1;
	}
	
	tcflush(socket_fd, 3);
	free(ctl_inf);
	
	return socket_fd;
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

void proxy_bt_socket(int client, int bt) {
	char *client_buf, *bt_buf;
    int nfds, x;
	fd_set R;
	size_t n;
	
	client_buf = malloc(0x2000);
	bt_buf = malloc(0x2000);
	
	nfds = client > bt ? client : bt;
	nfds++;
    
	while(1) {
		struct timeval to;
		FD_ZERO(&R);
        FD_SET(client, &R);
        FD_SET(bt, &R);
		
		to.tv_sec = 0;
		to.tv_usec = 100;
		x = select(nfds+1, &R, 0, 0, &to);
		if (x > 0) {
			if (FD_ISSET(client, &R)) {
                n = read(client, client_buf, 4096);
                if (n > 0) {
                    write(bt, client_buf, n);
                } else {
                    close(client);
                    NSLog(@"[!] Client read failed\n");
                    return;
                }
			}
			
			if (FD_ISSET(bt, &R)) {
                n = read(bt, bt_buf, 4096);
                if (n > 0) {
                    write(client, bt_buf, n);
                } else {
                    close(client);
                    NSLog(@"[!] H4 socket read failed\n");
                    return;
                }
			}
		} else if (x < 0 && errno != EINTR){
			NSLog(@"[!] Select failed with %s\n", strerror(errno));
			close(client);
			return;
		}
		
	}
}


