/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// libs/cutils/socket_loopback_client.c

#include "sockets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

#ifndef HAVE_WINSOCK
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#endif

#include "strutils.h"
extern int hostshell_mode;
/* Connect to port on the loopback IP interface. type is
 * SOCK_STREAM or SOCK_DGRAM. 
 * return is a file descriptor or -1 on error
 */
int socket_loopback_client(int port, int type)
{
    char zone_ipaddr[1025] = {0, };
    char name_vsm[1025] = {0, };
    int namelen;
    struct sockaddr_in addr;
    int s;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (hostshell_mode == 0) {
        FILE *fp;
        fp = popen("/usr/bin/vsm-foreground", "r");
        if (fp == NULL) {
            return 0;
        }
        fgets(name_vsm, 1025, fp);
        pclose(fp);

        snprintf(zone_ipaddr, 1025, "/usr/bin/vsm-info -i -n %s", name_vsm);
        fp = popen(zone_ipaddr, "r");
        if (fp == NULL) {
            return 0;
        }
        fgets(zone_ipaddr, 1025, fp);
        pclose(fp);

        //trim zone ipaddr
        namelen = strlen(zone_ipaddr);
        while (zone_ipaddr[--namelen] == '\n')
            ;
        zone_ipaddr[namelen + 1] = '\0';

        addr.sin_addr.s_addr = inet_addr(zone_ipaddr);
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    s = socket(AF_INET, type, 0);
    if(s < 0) return -1;

    if(connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    return s;
}

int socket_ifr_client(int port, int type, char *ifr_dev)
{
    int s;
    struct ifreq ifr;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) {
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    s_strncpy(ifr.ifr_name, ifr_dev, IFNAMSIZ-1);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0 ) {
        close(s);
        return -1;
    }

    char buf[1025] = {0, };
    inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, buf, sizeof(buf));
    addr.sin_addr.s_addr = inet_addr(buf);

    close(s);

    s = socket(AF_INET, type, 0);
    if(s < 0) {
        return -1;
    }

    if(connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    return s;
}

/* Simple implementation of ifconfig.
 * activate: '0' causes the ifname driver to be shut down.
 */
int ifconfig(char *ifname, char *address, char *netmask, int activated) {
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "cannot open socket\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    s_strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    sin = (struct sockaddr_in *) &ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = inet_addr(address);

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        fprintf(stderr,"cannot set SIOCSIFADDR flags: %s(errno:%d)\n", address, errno);
        close(sockfd);
        return -1;
    }

    sin->sin_addr.s_addr = inet_addr(netmask);
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        fprintf(stderr,"cannot set SIOCSIFNETMASK flags: %s(errno:%d)\n", netmask, errno);
        close(sockfd);
        return -1;
    }

    if (activated) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    } else {
        ifr.ifr_flags |= ~IFF_UP;
    }
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr,"cannot set SIOCGIFFLAGS flags: errno:%d\n", errno);
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}
