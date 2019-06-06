//
//  internalblue-ios-proxy.c
//  internalblue-ios-proxy
//
//  Created by ttdennis on 03.05.19.
//  Copyright © 2019 ttdennis. All rights reserved.
//

#include "internalblue-ios-proxy.h"

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

#define IOAOSSKYSETCHANNELSPEC 0x800C5414
#define IOAOSSKYGETCHANNELUUID 0x40105412

#define CTLIOCGINFO 0xC0644E03

typedef struct ctl_info {
    uint32_t ctl_id;
    char ctl_name[96];
} ctl_info_t;

int btwake_fd, bt_fd;

/*
 This code has been put together by reverse-engineering BlueTool and bluetoothd on
 iOS. Some of the things that happen here are not completely understood but the goal
 was to just get it to work.
 */
int connect_bt_device() {
	int socket_fd = socket(32, 1, 2);
	int error = 0;
	int ret = 0;
	
	struct sockaddr sock_addr;
	struct termios term;
	
	if (socket_fd == 0) {
		printf("unable to get bluetooth socket\n");
		return -1;
	}
	
	ctl_info_t *ctl_inf = malloc(sizeof(ctl_info_t));
    ctl_inf->ctl_id = 0;
	strcpy(ctl_inf->ctl_name, "com.apple.uart.bluetooth");
	if ((error = ioctl(socket_fd, CTLIOCGINFO, ctl_inf))) {
		printf("ioctl(CTLIOCGINFO) = %d - errno: %d\n", error, errno);
		printf("error: %s\n", strerror(errno));
		return -1;
	}
	
	*(int *)&sock_addr.sa_len = 0x22020;
	*(int *)&sock_addr.sa_data[2] = ctl_inf->ctl_id;
	ret = connect(socket_fd, &sock_addr, 0x20);
	if (ret != 0) {
		printf("connect() = %d - errno: %d\n", ret, errno);
		printf("error: %s\n", strerror(errno));
		return -1;
	}
	
	printf("Connected to bt device\n");
	
	socklen_t len = 72;
	
	ret = getsockopt(socket_fd, 2, TIOCGETA, &term, &len);
	if (ret != 0) {
		printf("getsockopt(TIOCGETA) = %d - errno: %d\n", ret, errno);
		printf("error: %s\n", strerror(errno));
		return -1;
	}
	
	cfmakeraw(&term);
	ret = cfsetspeed(&term, 3000000);
	if (ret != 0) {
		printf("cfsetspeed() = %d - errno: %d\n", ret, errno);
		printf("error: %s\n", strerror(errno));
		return -1;
	}
	
	term.c_iflag |= 4;
	term.c_cflag = 232192;
	ret = setsockopt(socket_fd, 2, TIOCSETA, &term, 0x48);
	if (ret != 0) {
		printf("setsockopt() = %d - errno: %d\n", ret, errno);
		printf("error: %s\n", strerror(errno));
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
		printf("Unable to create server socket\n");
		return -1;
	}
	
	addrlen = sizeof(server);
	memset(&server, '\0', addrlen);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);
	
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, 4);
	if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		printf("Error binding socket\n");
		return -1;
	}
	
	if (listen(server_fd, 5) < 0) {
		printf("Failed listening: %s\n", strerror(errno));
		return -1;
	}
	
	printf("Listening on port %d\n", port);
	
	return server_fd;
}

int wait_for_connection(int server_fd) {
	int client_fd;
	socklen_t len;
	struct sockaddr_in client;
	
	len = sizeof(struct sockaddr_in);
	client_fd = accept(server_fd, (struct sockaddr *)&client, (socklen_t *)&len);
	
	if (client_fd < 0) {
		printf("Accepting connection failed\n");
		return -1;
	}
	
	return client_fd;
}

size_t buffered_write(int fd, char *buf, int *len)
{
	size_t x = write(fd, buf, *len);
	if (x < 0)
		return x;
	if (x == 0)
		return x;
	if (x != *len)
		memmove(buf, buf+x, (*len)-x);
	*len -= x;
	return x;
}

void proxy_bt_socket(int client, int bt) {
	char *client_buf, *bt_buf;
	int nfds;
	fd_set R;
	int client_out = 0;
	int bt_out = 0;
	int x;
	size_t n;
	
	client_buf = malloc(1024);
	bt_buf = malloc(1024);
	
	nfds = client > bt ? client : bt;
	nfds++;
	
	while(1) {
		struct timeval to;
		if (client_out) {
			buffered_write(bt, client_buf, &client_out);
		}
		if (bt_out) {
			buffered_write(client, bt_buf, &bt_out);
		}
		FD_ZERO(&R);
		if (client_out < 1024)
			FD_SET(client, &R);
		if (bt_out < 1024)
			FD_SET(bt, &R);
		
		to.tv_sec = 0;
		to.tv_usec = 1000;
		x = select(nfds+1, &R, 0, 0, &to);
		if (x > 0) {
			if (FD_ISSET(client, &R)) {
				n = read(client, client_buf+client_out, 1024-client_out);
				if (n > 0) {
					client_out += n;
				} else {
					close(client);
					printf("Client read failed\n");
					return;
				}
			}
			
			if (FD_ISSET(bt, &R)) {
				n = read(bt, bt_buf+bt_out, 1024-bt_out);
				if (n > 0) {
					bt_out += n;
				} else {
					close(client);
					printf("BT read failed\n");
					return;
				}
			}
		} else if (x < 0 && errno != EINTR){
			printf("Select failed with %s\n", strerror(errno));
			close(client);
			return;
		}
		
	}
}

void __exit(int sig) {
	close(bt_fd);
	close(btwake_fd);
	exit(0);
}

int main(int argc, char **argv) {
	int server_fd, client_fd;
	int port;
	
	if (argc != 2) {
		printf("Usage: %s <port_number>\n", argv[0]);
		return 1;
	}
	
	port = atoi(argv[1]);
	
	// wake BT device
	btwake_fd = open("/dev/btwake", 0);
	
	bt_fd = connect_bt_device();
	if (bt_fd < 0) {
		printf("Error connecting to bluetooth device\n");
		return -1;
	}
	
	server_fd = create_server(port);
	if (server_fd < 0) {
		printf("Unable to create server\n");
		return -1;
	}
	printf("Created server\n");
	
	signal(SIGINT, __exit);
	
	while (1) {
		printf("Waiting for connection\n");
		client_fd = wait_for_connection(server_fd);
		if (client_fd < 0)
			continue;
		// currently only one connection is supported
		proxy_bt_socket(client_fd, bt_fd);
		close(client_fd);
	}
	
	return 0;
}
