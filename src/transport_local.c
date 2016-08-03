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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "sysdeps.h"
#include <sys/types.h>

#ifndef HAVE_WIN32_IPC
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#endif

#define  TRACE_TAG  TRACE_TRANSPORT
#include "sdb.h"
#include "strutils.h"
#if !SDB_HOST
#include "commandline_sdbd.h"
#endif

#ifdef HAVE_BIG_ENDIAN
#define H4(x)	(((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24)
static inline void fix_endians(apacket *p)
{
    p->msg.command     = H4(p->msg.command);
    p->msg.arg0        = H4(p->msg.arg0);
    p->msg.arg1        = H4(p->msg.arg1);
    p->msg.data_length = H4(p->msg.data_length);
    p->msg.data_check  = H4(p->msg.data_check);
    p->msg.magic       = H4(p->msg.magic);
}
#else
#define fix_endians(p) do {} while (0)
#endif

#if SDB_HOST
/* we keep a list of opened transports. The atransport struct knows to which
 * local transport it is connected. The list is used to detect when we're
 * trying to connect twice to a given local transport.
 */
#define  SDB_LOCAL_TRANSPORT_MAX  16

SDB_MUTEX_DEFINE( local_transports_lock );

static atransport*  local_transports[ SDB_LOCAL_TRANSPORT_MAX ];
#endif /* SDB_HOST */

SDB_MUTEX_DEFINE( register_noti_lock );
#ifndef _WIN32
static pthread_cond_t noti_cond = PTHREAD_COND_INITIALIZER;
#endif

static int remote_read(apacket *p, atransport *t)
{
    if(readx(t->sfd, &p->msg, sizeof(amessage))){
        D("remote local: read terminated (message)\n");
        return -1;
    }

    fix_endians(p);

#if 0 && defined HAVE_BIG_ENDIAN
    D("read remote packet: %04x arg0=%0x arg1=%0x data_length=%0x data_check=%0x magic=%0x\n",
      p->msg.command, p->msg.arg0, p->msg.arg1, p->msg.data_length, p->msg.data_check, p->msg.magic);
#endif
    if(check_header(p)) {
        D("bad header: terminated (data)\n");
        return -1;
    }

    if(readx(t->sfd, p->data, p->msg.data_length)){
        D("remote local: terminated (data)\n");
        return -1;
    }

    if(check_data(p)) {
        D("bad data: terminated (data)\n");
        return -1;
    }

    return 0;
}

static int remote_write(apacket *p, atransport *t)
{
    int   length = p->msg.data_length;

    fix_endians(p);

#if 0 && defined HAVE_BIG_ENDIAN
    D("write remote packet: %04x arg0=%0x arg1=%0x data_length=%0x data_check=%0x magic=%0x\n",
      p->msg.command, p->msg.arg0, p->msg.arg1, p->msg.data_length, p->msg.data_check, p->msg.magic);
#endif
    if(writex(t->sfd, &p->msg, sizeof(amessage) + length)) {
        D("remote local: write terminated\n");
        return -1;
    }

    return 0;
}


int local_connect(int port, const char *device_name) {
    return local_connect_arbitrary_ports(port-1, port, device_name);
}

int local_connect_arbitrary_ports(int console_port, int sdb_port, const char *device_name)
{
    char buf[64];
    int  fd = -1;

#if SDB_HOST
    const char *host = getenv("SDBHOST");
    if (host) {
        fd = socket_network_client(host, sdb_port, SOCK_STREAM);
    }
#endif
    if (fd < 0) {
        fd = socket_loopback_client(sdb_port, SOCK_STREAM);
    }

    if (fd >= 0) {
        D("client: connected on remote on fd %d\n", fd);
        if (close_on_exec(fd) < 0) {
            D("failed to close fd exec\n");
        }
        disable_tcp_nagle(fd);
        snprintf(buf, sizeof buf, "%s%d", LOCAL_CLIENT_PREFIX, console_port);
        register_socket_transport(fd, buf, sdb_port, 1, device_name);
        return 0;
    }
    return -1;
}

#if SDB_HOST /* tizen specific */
int get_devicename_from_shdmem(int port, char *device_name)
{
    char *vms = NULL;
#ifndef HAVE_WIN32_IPC
    int shm_id;
    void *shared_memory = (void *)0;

    shm_id = shmget( (key_t)port-1, 0, 0);
    if (shm_id == -1)
        return -1;

    shared_memory = shmat(shm_id, (void *)0, SHM_RDONLY);

    if (shared_memory == (void *)-1)
    {
        D("faild to get shdmem key (%d) : %s\n", port, strerror(errno));
        return -1;
    }

    vms = strstr((char*)shared_memory, VMS_PATH);
    if (vms != NULL)
        s_strncpy(device_name, vms+strlen(VMS_PATH), DEVICENAME_MAX);
    else
        s_strncpy(device_name, DEFAULT_DEVICENAME, DEVICENAME_MAX);

#else /* _WIN32*/
    HANDLE hMapFile;
    char s_port[5];
    char* pBuf;

    sprintf(s_port, "%d", port-1);
    hMapFile = OpenFileMapping(FILE_MAP_READ, TRUE, s_port);

    if(hMapFile == NULL) {
        D("faild to get shdmem key (%ld) : %s\n", port, GetLastError() );
        return -1;
    }
    pBuf = (char*)MapViewOfFile(hMapFile,
                            FILE_MAP_READ,
                            0,
                            0,
                            50);
    if (pBuf == NULL) {
        D("Could not map view of file (%ld)\n", GetLastError());
        CloseHandle(hMapFile);
        return -1;
    }

    vms = strstr((char*)pBuf, VMS_PATH);
    if (vms != NULL)
        s_strncpy(device_name, vms+strlen(VMS_PATH), DEVICENAME_MAX);
    else
        s_strncpy(device_name, DEFAULT_DEVICENAME, DEVICENAME_MAX);
    CloseHandle(hMapFile);
#endif
    D("init device name %s on port %d\n", device_name, port);

    return 0;
}

int read_line(const int fd, char* ptr, size_t maxlen)
{
    unsigned int n = 0;
    char c[2];
    int rc;

    while(n != maxlen) {
        if((rc = sdb_read(fd, c, 1)) != 1)
            return -1; // eof or read err

        if(*c == '\n') {
            ptr[n] = 0;
            return n;
        }
        ptr[n++] = *c;
    }
    return -1; // no space
}
#endif

static void *client_socket_thread(void *x)
{
#if SDB_HOST
    int  port  = DEFAULT_SDB_LOCAL_TRANSPORT_PORT;
    int  count = SDB_LOCAL_TRANSPORT_MAX;

    D("transport: client_socket_thread() starting\n");

    /* try to connect to any number of running emulator instances     */
    /* this is only done when SDB starts up. later, each new emulator */
    /* will send a message to SDB to indicate that is is starting up  */
    for ( ; count > 0; count--, port += 10 ) { /* tizen specific */
        (void) local_connect(port, NULL);
    }
#endif
    return 0;
}

static void *server_socket_thread(void * arg)
{
    int serverfd, fd;
    struct sockaddr_in addr;
    socklen_t alen;
    int port = (int)arg;

    D("transport: server_socket_thread() starting\n");
    serverfd = -1;
    for(;;) {
        if(serverfd == -1) {
            // socket_inaddr_any_server returns -1 if there is any error
            serverfd = socket_inaddr_any_server(port, SOCK_STREAM);
            if(serverfd < 0) {
                D("server: cannot bind socket yet\n");
                sdb_sleep_ms(1000);
                continue;
            }
            if (close_on_exec(serverfd) < 0) {
                D("failed to close serverfd exec\n");
            }
        }

        alen = sizeof(addr);
        D("server: trying to get new connection from %d\n", port);

        if (is_emulator()) {
            // im ready to accept new client!
            pthread_cond_broadcast(&noti_cond);
        }

        fd = sdb_socket_accept(serverfd, (struct sockaddr *)&addr, &alen);
        if(fd >= 0) {
            D("server: new connection on fd %d\n", fd);
            if (close_on_exec(fd) < 0) {
                D("failed to close fd exec\n");
            }
            disable_tcp_nagle(fd);

            // Check the peer ip validation.
            if (!is_emulator()
                && !request_plugin_verification(SDBD_CMD_VERIFY_PEERIP, inet_ntoa(addr.sin_addr))) {
                sdb_close(fd);
            } else {
                register_socket_transport(fd, "host", port, 1, NULL);
            }
        } else {
            D("failed to accept() from sdb server\n");
            //FIXME: implements error handle for EMFILE or ENFILE
        }
    }
    D("transport: server_socket_thread() exiting\n");
    return 0;
}

/* This is relevant only for SDB daemon running inside the emulator. */
#if !SDB_HOST
/*
 * Redefine open and write for qemu_pipe.h that contains inlined references
 * to those routines. We will redifine them back after qemu_pipe.h inclusion.
 */
#undef open
#undef write
#define open    sdb_open
#define write   sdb_write
#include "qemu_pipe.h"
#undef open
#undef write
#define open    ___xxx_open
#define write   ___xxx_write

/* A worker thread that monitors host connections, and registers a transport for
 * every new host connection. This thread replaces server_socket_thread on
 * condition that sdbd daemon runs inside the emulator, and emulator uses QEMUD
 * pipe to communicate with sdbd daemon inside the guest. This is done in order
 * to provide more robust communication channel between SDB host and guest. The
 * main issue with server_socket_thread approach is that it runs on top of TCP,
 * and thus is sensitive to network disruptions. For instance, the
 * ConnectionManager may decide to reset all network connections, in which case
 * the connection between SDB host and guest will be lost. To make SDB traffic
 * independent from the network, we use here 'sdb' QEMUD service to transfer data
 * between the host, and the guest. See external/qemu/android/sdb-*.* that
 * implements the emulator's side of the protocol. Another advantage of using
 * QEMUD approach is that SDB will be up much sooner, since it doesn't depend
 * anymore on network being set up.
 * The guest side of the protocol contains the following phases:
 * - Connect with sdb QEMUD service. In this phase a handle to 'sdb' QEMUD service
 *   is opened, and it becomes clear whether or not emulator supports that
 *   protocol.
 * - Wait for the SDB host to create connection with the guest. This is done by
 *   sending an 'accept' request to the sdb QEMUD service, and waiting on
 *   response.
 * - When new SDB host connection is accepted, the connection with sdb QEMUD
 *   service is registered as the transport, and a 'start' request is sent to the
 *   sdb QEMUD service, indicating that the guest is ready to receive messages.
 *   Note that the guest will ignore messages sent down from the emulator before
 *   the transport registration is completed. That's why we need to send the
 *   'start' request after the transport is registered.
 */
#if 0
static void *qemu_socket_thread(void * arg)
{
/* 'accept' request to the sdb QEMUD service. */
static const char _accept_req[] = "accept";
/* 'start' request to the sdb QEMUD service. */
static const char _start_req[]  = "start";
/* 'ok' reply from the sdb QEMUD service. */
static const char _ok_resp[]    = "ok";

    const int port = (int)arg;
    int res, fd;
    char tmp[256];
    char con_name[32];

    D("transport: qemu_socket_thread() starting\n");

    /* sdb QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "qemud:sdb:%d", port);

    /* Connect to the sdb QEMUD service. */
    fd = qemu_pipe_open(con_name);
    if (fd < 0) {
        /* This could be an older version of the emulator, that doesn't
         * implement sdb QEMUD service. Fall back to the old TCP way. */
        sdb_thread_t thr;
        D("sdb service is not available. Falling back to TCP socket.\n");
        sdb_thread_create(&thr, server_socket_thread, arg);
        return 0;
    }

    for(;;) {
        /*
         * Wait till the host creates a new connection.
         */

        /* Send the 'accept' request. */
        res = sdb_write(fd, _accept_req, strlen(_accept_req));
        if (res == strlen(_accept_req)) {
            /* Wait for the response. In the response we expect 'ok' on success,
             * or 'ko' on failure. */
            res = sdb_read(fd, tmp, sizeof(tmp));
            if (res != 2 || memcmp(tmp, _ok_resp, 2)) {
                D("Accepting SDB host connection has failed.\n");
                sdb_close(fd);
            } else {
                /* Host is connected. Register the transport, and start the
                 * exchange. */
                register_socket_transport(fd, "host", port, 1, NULL);
                sdb_write(fd, _start_req, strlen(_start_req));
            }

            /* Prepare for accepting of the next SDB host connection. */
            fd = qemu_pipe_open(con_name);
            if (fd < 0) {
                D("sdb service become unavailable.\n");
                return 0;
            }
        } else {
            D("Unable to send the '%s' request to SDB service.\n", _accept_req);
            return 0;
        }
    }
    D("transport: qemu_socket_thread() exiting\n");
    return 0;
}
#endif  // !SDB_HOST
#endif

int connect_nonb(int sockfd, const struct sockaddr *saptr, socklen_t salen,
        int nsec) {
    int flags, n, error;
    socklen_t len;
    fd_set rset, wset;
    struct timeval tval;

    flags = fcntl(sockfd, F_GETFL, 0);
    if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        D("failed to set file O_NONBLOCK status flag for socket %d: errno:%d\n",
                     sockfd, errno);
    }

    error = 0;
    if ((n = connect(sockfd, (struct sockaddr *) saptr, salen)) < 0)
        if (errno != EINPROGRESS)
            return (-1);

    /* Do whatever we want while the connect is taking place. */

    if (n == 0)
        goto done;
    /* connect completed immediately */

    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    wset = rset;
    tval.tv_sec = nsec;
    tval.tv_usec = 0;
    if ((n = select(sockfd + 1, &rset, &wset, NULL, nsec ? &tval : NULL))
            == 0) {
        sdb_close(sockfd); /* timeout */
        errno = ETIMEDOUT;
        return (-1);
    }
    if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
        len = sizeof(error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
            return (-1); /* Solaris pending error */
    } else
        D("select error: sockfd not set\n");

    done:
    if(fcntl(sockfd, F_SETFL, flags) == -1) { /* restore file status flags */
        D("failed to restore file status flag for socket %d\n",
                 sockfd);
    }

    if (error) {
        sdb_close(sockfd); /* just in case */
        errno = error;
        return (-1);
    }
    return (0);
}

static int send_msg_to_localhost_from_guest(const char *host_ip, int local_port, char *request, int sock_type) {
    int                  ret, s;
    struct sockaddr_in   server;
    int connect_timeout = 1;
    memset( &server, 0, sizeof(server) );
    server.sin_family      = AF_INET;
    server.sin_port        = htons(local_port);
    server.sin_addr.s_addr = inet_addr(host_ip);

    D("try to send notification to host(%s:%d) using %s:[%s]\n", host_ip, local_port, (sock_type == 0) ? "tcp" : "udp", request);

    if (sock_type == 0) {
        s = socket(AF_INET, SOCK_STREAM, 0);
    } else {
        s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    if (s < 0) {
        D("could not create socket\n");
        return -1;
    }
    ret = connect_nonb(s, (struct sockaddr*) &server, sizeof(server), connect_timeout);
    if (ret < 0) {
        D("could not connect to server\n");
        sdb_close(s);
        return -1;
    }
    if (writex(s, request, strlen(request)) != 0) {
        D("could not send notification request to host\n");
        sdb_close(s);
        return -1;
    }
    sdb_close(s);
    D("sent notification request to host\n");

    return 0;
}

// send the "emulator" request to sdbserver
static void* notify_sdbd_startup_thread(void* ptr) {
    char                 buffer[512];
    char                 request[512];

    SdbdCommandlineArgs *sdbd_args = &sdbd_commandline_args; // alias

    // send the request to sdbserver
    char vm_name[256]={0,};
    char host_ip[256] = {0,};
    char guest_ip[256] = {0,};
    int sensors_port = sdbd_args->sensors.port;
    int emulator_port = sdbd_args->emulator.port;

    int r = get_emulator_name(vm_name, sizeof vm_name);
    int time = 0;
    //int try_limit_time = -1; // try_limit_time < 0 if unlimited
    if (sensors_port < 0 || emulator_port < 0 || r < 0) {
        return NULL;
    }
    if (get_emulator_hostip(host_ip, sizeof host_ip) == -1) {
       D("failed to get emulator host ip\n");
       return NULL;
    }
    // XXX: Known issue - log collision
    while (1) {
        // Trial limitation reached. terminate notify thread.
        /*if (0 <= try_limit_time && try_limit_time <= time) {
            break;
        }*/
        // If there is any connected (via TCP/IP) SDB server, sleep 10 secs
        if (get_connected_count(kTransportLocal) > 0) {
            if (time >= 0) {
                time = 0;
                D("notify_sdbd_startup() success after %d trial(s)\n", time);
            }
            sleep(10);
            continue;
        }

        if (get_emulator_guestip(guest_ip, sizeof guest_ip) == -1) {
			D("failed to get emulator guest ip\n");
			goto sleep_and_continue;
		}

        // tell qemu sdbd is just started with udp
        if (send_msg_to_localhost_from_guest(host_ip, sensors_port, "2\n", 1) < 0) {
            D("could not send sensord noti request, try again %dth\n", time+1);
            goto sleep_and_continue;
        }

        // tell sdb server emulator's vms name
        // TODO: should we use host:emulator request? let's talk about this!

        if (!strncmp(host_ip, QEMU_FORWARD_IP, sizeof host_ip)) {
            snprintf(request, sizeof request, "host:emulator:%d:%s", (emulator_port + 1), vm_name);
        } else {
            snprintf(request, sizeof request, "host:connect:%s:%d", guest_ip, DEFAULT_SDB_LOCAL_TRANSPORT_PORT);
        }
        D("[%s:%d] request:%s \n", __FUNCTION__, __LINE__, request);
        snprintf(buffer, sizeof buffer, "%04x%s", strlen(request), request );

        if (send_msg_to_localhost_from_guest(host_ip, DEFAULT_SDB_PORT, buffer, 0) <0) {
            D("could not send sdbd noti request. it might sdb server has not been started yet.\n");
            goto sleep_and_continue;
        }
        //LOGI("sdbd noti request sent.\n");

sleep_and_continue:
        time++;
        sleep(1);
    }
}

void local_init(int port)
{
    sdb_thread_t thr;
    void* (*func)(void *);

    if(HOST) {
        func = client_socket_thread;
    } else {
#if SDB_HOST
        func = server_socket_thread;
#else
        /* For the sdbd daemon in the system image we need to distinguish
         * between the device, and the emulator. */
#if 0 /* tizen specific */
        char is_qemu[PROPERTY_VALUE_MAX];
        property_get("ro.kernel.qemu", is_qemu, "");
        if (!strcmp(is_qemu, "1")) {
            /* Running inside the emulator: use QEMUD pipe as the transport. */
            func = qemu_socket_thread;
        } else
#endif
        {
            /* Running inside the device: use TCP socket as the transport. */
            func = server_socket_thread;
        }
#endif // !SDB_HOST
    }

    D("transport: local %s init\n", HOST ? "client" : "server");

    if(sdb_thread_create(&thr, func, (void *)port)) {
        fatal_errno("cannot create local socket %s thread",
                    HOST ? "client" : "server");
    }

    /*
     * wait until server socket thread made!
     * get noti from server_socket_thread
     */
    if (is_emulator()) {
        sdb_mutex_lock(&register_noti_lock);
        pthread_cond_wait(&noti_cond, &register_noti_lock);

        // thread start
        if(sdb_thread_create(&thr, notify_sdbd_startup_thread, NULL)) {
            fatal("cannot create notify_sdbd_startup_thread");
            //notify_sdbd_startup(); // defensive code
        }
        sdb_mutex_unlock(&register_noti_lock);
    }
}

static void remote_kick(atransport *t)
{
    int fd = t->sfd;
    t->sfd = -1;
    sdb_shutdown(fd);
    sdb_close(fd);

#if SDB_HOST
    if(HOST) {
        int  nn;
        sdb_mutex_lock( &local_transports_lock );
        for (nn = 0; nn < SDB_LOCAL_TRANSPORT_MAX; nn++) {
            if (local_transports[nn] == t) {
                local_transports[nn] = NULL;
                break;
            }
        }
        sdb_mutex_unlock( &local_transports_lock );
    }
#endif
}

static void remote_close(atransport *t)
{
    sdb_close(t->fd);
}


#if SDB_HOST
/* Only call this function if you already hold local_transports_lock. */
atransport* find_emulator_transport_by_sdb_port_locked(int sdb_port)
{
    int i;
    for (i = 0; i < SDB_LOCAL_TRANSPORT_MAX; i++) {
        if (local_transports[i] && local_transports[i]->sdb_port == sdb_port) {
            return local_transports[i];
        }
    }
    return NULL;
}

atransport* find_emulator_transport_by_sdb_port(int sdb_port)
{
    sdb_mutex_lock( &local_transports_lock );
    atransport* result = find_emulator_transport_by_sdb_port_locked(sdb_port);
    sdb_mutex_unlock( &local_transports_lock );
    return result;
}

/* Only call this function if you already hold local_transports_lock. */
int get_available_local_transport_index_locked()
{
    int i;
    for (i = 0; i < SDB_LOCAL_TRANSPORT_MAX; i++) {
        if (local_transports[i] == NULL) {
            return i;
        }
    }
    return -1;
}

int get_available_local_transport_index()
{
    sdb_mutex_lock( &local_transports_lock );
    int result = get_available_local_transport_index_locked();
    sdb_mutex_unlock( &local_transports_lock );
    return result;
}
#endif

int init_socket_transport(atransport *t, int s, int sdb_port, int local)
{
    int  fail = 0;

    t->kick = remote_kick;
    t->close = remote_close;
    t->read_from_remote = remote_read;
    t->write_to_remote = remote_write;
    t->sfd = s;
    t->sync_token = 1;
    t->connection_state = CS_OFFLINE;
    t->type = kTransportLocal;
    t->sdb_port = 0;

#if SDB_HOST
    if (HOST && local) {
        sdb_mutex_lock( &local_transports_lock );
        {
            t->sdb_port = sdb_port;
            atransport* existing_transport =
                    find_emulator_transport_by_sdb_port_locked(sdb_port);
            int index = get_available_local_transport_index_locked();
            if (existing_transport != NULL) {
                D("local transport for port %d already registered (%p)?\n",
                sdb_port, existing_transport);
                fail = -1;
            } else if (index < 0) {
                // Too many emulators.
                D("cannot register more emulators. Maximum is %d\n",
                        SDB_LOCAL_TRANSPORT_MAX);
                fail = -1;
            } else {
                local_transports[index] = t;
            }
       }
       sdb_mutex_unlock( &local_transports_lock );
    }
#endif
    return fail;
}
