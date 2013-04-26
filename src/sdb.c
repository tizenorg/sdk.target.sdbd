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

#define  TRACE_TAG   TRACE_SDB

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <grp.h>

#include "sysdeps.h"
#include "sdb.h"

#if !SDB_HOST
//#include <private/android_filesystem_config.h> eric
#include <linux/capability.h>
#include <linux/prctl.h>
#define SDB_PIDPATH "/tmp/.sdbd.pid"
#else
#include "usb_vendors.h"
#endif

#if SDB_TRACE
SDB_MUTEX_DEFINE( D_lock );
#endif

int HOST = 0;

void handle_sig_term(int sig) {
#ifdef SDB_PIDPATH
    if (access(SDB_PIDPATH, F_OK) == 0)
        sdb_unlink(SDB_PIDPATH);
#endif
    //kill(getpgid(getpid()),SIGTERM);
    //killpg(getpgid(getpid()),SIGTERM);
    if (access("/dev/samsung_sdb", F_OK) == 0) {
        exit(0);
    } else {
    	// do nothing on a emulator
    }
}

static const char *sdb_device_banner = "device";

void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void fatal_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: %s: ", strerror(errno));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

int   sdb_trace_mask;

/* read a comma/space/colum/semi-column separated list of tags
 * from the SDB_TRACE environment variable and build the trace
 * mask from it. note that '1' and 'all' are special cases to
 * enable all tracing
 */
void  sdb_trace_init(void)
{
    const char*  p = getenv("SDB_TRACE");
    const char*  q;

    static const struct {
        const char*  tag;
        int           flag;
    } tags[] = {
        { "1", 0 },
        { "all", 0 },
        { "sdb", TRACE_SDB },
        { "sockets", TRACE_SOCKETS },
        { "packets", TRACE_PACKETS },
        { "rwx", TRACE_RWX },
        { "usb", TRACE_USB },
        { "sync", TRACE_SYNC },
        { "sysdeps", TRACE_SYSDEPS },
        { "transport", TRACE_TRANSPORT },
        { "jdwp", TRACE_JDWP },
        { "services", TRACE_SERVICES },
        { "properties", TRACE_PROPERTIES },
        { "sdktools", TRACE_SDKTOOLS },
        { NULL, 0 }
    };

    if (p == NULL)
            return;

    /* use a comma/column/semi-colum/space separated list */
    while (*p) {
        int  len, tagn;

        q = strpbrk(p, " ,:;");
        if (q == NULL) {
            q = p + strlen(p);
        }
        len = q - p;

        for (tagn = 0; tags[tagn].tag != NULL; tagn++)
        {
            int  taglen = strlen(tags[tagn].tag);

            if (len == taglen && !memcmp(tags[tagn].tag, p, len) )
            {
                int  flag = tags[tagn].flag;
                if (flag == 0) {
                    sdb_trace_mask = ~0;
                    return;
                }
                sdb_trace_mask |= (1 << flag);
                break;
            }
        }
        p = q;
        if (*p)
            p++;
    }
}

#if !SDB_HOST
/*
 * Implements SDB tracing inside the emulator.
 */

#include <stdarg.h>

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

/* A handle to sdb-debug qemud service in the emulator. */
int   sdb_debug_qemu = -1;

/* Initializes connection with the sdb-debug qemud service in the emulator. */
#if 0 /* doen't support in Tizen */
static int sdb_qemu_trace_init(void)
{
    char con_name[32];

    if (sdb_debug_qemu >= 0) {
        return 0;
    }

    /* sdb debugging QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "qemud:sdb-debug");
    sdb_debug_qemu = qemu_pipe_open(con_name);
    return (sdb_debug_qemu >= 0) ? 0 : -1;
}

void sdb_qemu_trace(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char msg[1024];

    if (sdb_debug_qemu >= 0) {
        vsnprintf(msg, sizeof(msg), fmt, args);
        sdb_write(sdb_debug_qemu, msg, strlen(msg));
    }
}
#endif
#endif  /* !SDB_HOST */

apacket *get_apacket(void)
{
    apacket *p = malloc(sizeof(apacket));
    if(p == 0) fatal("failed to allocate an apacket");
    memset(p, 0, sizeof(apacket) - MAX_PAYLOAD);
    return p;
}

void put_apacket(apacket *p)
{
    if (p != NULL) {
        free(p);
        p = NULL;
    }
}

void handle_online(void)
{
    D("sdb: online\n");
}

void handle_offline(atransport *t)
{
    D("sdb: offline\n");
    //Close the associated usb
    run_transport_disconnects(t);
}

#if TRACE_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    char *tag;
    char *x;
    unsigned count;

    switch(p->msg.command){
    case A_SYNC: tag = "SYNC"; break;
    case A_CNXN: tag = "CNXN" ; break;
    case A_OPEN: tag = "OPEN"; break;
    case A_OKAY: tag = "OKAY"; break;
    case A_CLSE: tag = "CLSE"; break;
    case A_WRTE: tag = "WRTE"; break;
    default: tag = "????"; break;
    }

    fprintf(stderr, "%s: %s %08x %08x %04x \"",
            label, tag, p->msg.arg0, p->msg.arg1, p->msg.data_length);
    count = p->msg.data_length;
    x = (char*) p->data;
    if(count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while(count-- > 0){
        if((*x >= ' ') && (*x < 127)) {
            fputc(*x, stderr);
        } else {
            fputc('.', stderr);
        }
        x++;
    }
    fprintf(stderr, tag);
}
#endif

static void send_ready(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_ready \n");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close \n");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_connect(atransport *t)
{
    D("Calling send_connect \n");
    apacket *cp = get_apacket();
    cp->msg.command = A_CNXN;
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = MAX_PAYLOAD;
    snprintf((char*) cp->data, sizeof cp->data, "%s::",
            HOST ? "host" : sdb_device_banner);
    cp->msg.data_length = strlen((char*) cp->data) + 1;
    send_packet(cp, t);
#if SDB_HOST
        /* XXX why sleep here? */
    // allow the device some time to respond to the connect message
    sdb_sleep_ms(1000);
#endif
}

static char *connection_state_name(atransport *t)
{
    if (t == NULL) {
        return "unknown";
    }

    switch(t->connection_state) {
    case CS_BOOTLOADER:
        return "bootloader";
    case CS_DEVICE:
        return "device";
    case CS_OFFLINE:
        return "offline";
    default:
        return "unknown";
    }
}

void parse_banner(char *banner, atransport *t)
{
    char *type, *product, *end;

    D("parse_banner: %s\n", banner);
    type = banner;
    product = strchr(type, ':');
    if(product) {
        *product++ = 0;
    } else {
        product = "";
    }

        /* remove trailing ':' */
    end = strchr(product, ':');
    if(end) *end = 0;

        /* save product name in device structure */
    if (t->product == NULL) {
        t->product = strdup(product);
    } else if (strcmp(product, t->product) != 0) {
        free(t->product);
        t->product = strdup(product);
    }

    if(!strcmp(type, "bootloader")){
        D("setting connection_state to CS_BOOTLOADER\n");
        t->connection_state = CS_BOOTLOADER;
        update_transports();
        return;
    }

    if(!strcmp(type, "device")) {
        D("setting connection_state to CS_DEVICE\n");
        t->connection_state = CS_DEVICE;
        update_transports();
        return;
    }

    if(!strcmp(type, "recovery")) {
        D("setting connection_state to CS_RECOVERY\n");
        t->connection_state = CS_RECOVERY;
        update_transports();
        return;
    }

    if(!strcmp(type, "sideload")) {
        D("setting connection_state to CS_SIDELOAD\n");
        t->connection_state = CS_SIDELOAD;
        update_transports();
        return;
    }

    t->connection_state = CS_HOST;
}

void handle_packet(apacket *p, atransport *t)
{
    asocket *s;

    D("handle_packet() %c%c%c%c\n", ((char*) (&(p->msg.command)))[0],
                ((char*) (&(p->msg.command)))[1],
                ((char*) (&(p->msg.command)))[2],
                ((char*) (&(p->msg.command)))[3]);

    print_packet("recv", p);

    switch(p->msg.command){
    case A_SYNC:
        if(p->msg.arg0){
            send_packet(p, t);
            if(HOST) send_connect(t);
        } else {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN: /* CONNECT(version, maxdata, "system-id-string") */
            /* XXX verify version, etc */
        if(t->connection_state != CS_OFFLINE) {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
        }
        parse_banner((char*) p->data, t);
        handle_online();
        if(!HOST) send_connect(t);
        break;

    case A_OPEN: /* OPEN(local-id, 0, "destination") */
        if(t->connection_state != CS_OFFLINE) {
            char *name = (char*) p->data;
            name[p->msg.data_length > 0 ? p->msg.data_length - 1 : 0] = 0;
            s = create_local_service_socket(name);
            if(s == 0) {
                send_close(0, p->msg.arg0, t);
            } else {
                s->peer = create_remote_socket(p->msg.arg0, t);
                s->peer->peer = s;
                send_ready(s->id, s->peer->id, t);
                s->ready(s);
            }
        }
        break;

    case A_OKAY: /* READY(local-id, remote-id, "") */
        if(t->connection_state != CS_OFFLINE) {
            if((s = find_local_socket(p->msg.arg1))) {
                if(s->peer == 0) {
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;
                }
                s->ready(s);
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") */
        if(t->connection_state != CS_OFFLINE) {
            if((s = find_local_socket(p->msg.arg1))) {
                s->close(s);
            }
        }
        break;

    case A_WRTE:
        if(t->connection_state != CS_OFFLINE) {
            if((s = find_local_socket(p->msg.arg1))) {
                unsigned rid = p->msg.arg0;
                p->len = p->msg.data_length;

                if(s->enqueue(s, p) == 0) {
                    D("Enqueue the socket\n");
                    send_ready(s->id, rid, t);
                }
                return;
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}

alistener listener_list = {
    .next = &listener_list,
    .prev = &listener_list,
};

static void ss_listener_event_func(int _fd, unsigned ev, void *_l)
{
    asocket *s;

    if(ev & FDE_READ) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        fd = sdb_socket_accept(_fd, &addr, &alen);
        if(fd < 0) return;

        sdb_socket_setbufsize(fd, CHUNK_SIZE);

        s = create_local_socket(fd);
        if(s) {
            connect_to_smartsocket(s);
            return;
        }

        sdb_close(fd);
    }
}

static void listener_event_func(int _fd, unsigned ev, void *_l)
{
    alistener *l = _l;
    asocket *s;

    if(ev & FDE_READ) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        fd = sdb_socket_accept(_fd, &addr, &alen);
        if(fd < 0) return;

        s = create_local_socket(fd);
        if(s) {
            s->transport = l->transport;
            connect_to_remote(s, l->connect_to);
            return;
        }

        sdb_close(fd);
    }
}

static void  free_listener(alistener*  l)
{
    if (l->next) {
        l->next->prev = l->prev;
        l->prev->next = l->next;
        l->next = l->prev = l;
    }

    // closes the corresponding fd
    fdevent_remove(&l->fde);

    if (l->local_name)
        free((char*)l->local_name);

    if (l->connect_to)
        free((char*)l->connect_to);

    if (l->transport) {
        remove_transport_disconnect(l->transport, &l->disconnect);
    }
    free(l);
}

static void listener_disconnect(void*  _l, atransport*  t)
{
    alistener*  l = _l;

    free_listener(l);
}

int local_name_to_fd(const char *name)
{
    int port;

    if(!strncmp("tcp:", name, 4)){
        int  ret;
        port = atoi(name + 4);
        ret = socket_loopback_server(port, SOCK_STREAM);
        return ret;
    }
#ifndef HAVE_WIN32_IPC  /* no Unix-domain sockets on Win32 */
    // It's non-sensical to support the "reserved" space on the sdb host side
    if(!strncmp(name, "local:", 6)) {
        return socket_local_server(name + 6,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localabstract:", 14)) {
        return socket_local_server(name + 14,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localfilesystem:", 16)) {
        return socket_local_server(name + 16,
                ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
    }

#endif
    printf("unknown local portname '%s'\n", name);
    return -1;
}

static int remove_listener(const char *local_name, const char *connect_to, atransport* transport)
{
    alistener *l;

    for (l = listener_list.next; l != &listener_list; l = l->next) {
        if (!strcmp(local_name, l->local_name) &&
            !strcmp(connect_to, l->connect_to) &&
            l->transport && l->transport == transport) {

            listener_disconnect(l, transport);
            return 0;
        }
    }

    return -1;
}

static int install_listener(const char *local_name, const char *connect_to, atransport* transport)
{
    alistener *l;

    //printf("install_listener('%s','%s')\n", local_name, connect_to);

    for(l = listener_list.next; l != &listener_list; l = l->next){
        if(strcmp(local_name, l->local_name) == 0) {
            char *cto;

                /* can't repurpose a smartsocket */
            if(l->connect_to[0] == '*') {
                return -1;
            }

            cto = strdup(connect_to);
            if(cto == 0) {
                return -1;
            }

            //printf("rebinding '%s' to '%s'\n", local_name, connect_to);
            free((void*) l->connect_to);
            l->connect_to = cto;
            if (l->transport != transport) {
                remove_transport_disconnect(l->transport, &l->disconnect);
                l->transport = transport;
                add_transport_disconnect(l->transport, &l->disconnect);
            }
            return 0;
        }
    }

    if((l = calloc(1, sizeof(alistener))) == 0) goto nomem;
    if((l->local_name = strdup(local_name)) == 0) goto nomem;
    if((l->connect_to = strdup(connect_to)) == 0) goto nomem;


    l->fd = local_name_to_fd(local_name);
    if(l->fd < 0) {
        free((void*) l->local_name);
        free((void*) l->connect_to);
        free(l);
        printf("cannot bind '%s'\n", local_name);
        return -2;
    }

    if (close_on_exec(l->fd) < 0) {
        D("fail to close fd exec:%d\n",l->fd);
    }
    if(!strcmp(l->connect_to, "*smartsocket*")) {
        fdevent_install(&l->fde, l->fd, ss_listener_event_func, l);
    } else {
        fdevent_install(&l->fde, l->fd, listener_event_func, l);
    }
    fdevent_set(&l->fde, FDE_READ);

    l->next = &listener_list;
    l->prev = listener_list.prev;
    l->next->prev = l;
    l->prev->next = l;
    l->transport = transport;

    if (transport) {
        l->disconnect.opaque = l;
        l->disconnect.func   = listener_disconnect;
        add_transport_disconnect(transport, &l->disconnect);
    }
    return 0;

nomem:
    fatal("cannot allocate listener");
    return 0;
}

#ifdef HAVE_WIN32_PROC
static BOOL WINAPI ctrlc_handler(DWORD type)
{
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}
#endif

static void sdb_cleanup(void)
{
    usb_cleanup();
}

void start_logging(void)
{
#ifdef HAVE_WIN32_PROC
    char    temp[ MAX_PATH ];
    FILE*   fnul;
    FILE*   flog;

    GetTempPath( sizeof(temp) - 8, temp );
    strcat( temp, "sdb.log" );

    /* Win32 specific redirections */
    fnul = fopen( "NUL", "rt" );
    if (fnul != NULL)
        stdin[0] = fnul[0];

    flog = fopen( temp, "at" );
    if (flog == NULL)
        flog = fnul;

    setvbuf( flog, NULL, _IONBF, 0 );

    stdout[0] = flog[0];
    stderr[0] = flog[0];
    fprintf(stderr,"--- sdb starting (pid %d) ---\n", getpid());
#else
    int fd;

    fd = unix_open("/dev/null", O_RDONLY);
    if (fd < 0) {
        // hopefully not gonna happen
        return;
    }
    dup2(fd, 0);
    sdb_close(fd);

    fd = unix_open("/tmp/sdb.log", O_WRONLY | O_CREAT | O_APPEND, 0640);
    if(fd < 0) {
        fd = unix_open("/dev/null", O_WRONLY);
        if (fd < 0) {
            // hopefully not gonna happen
            return;
        }
    }
    dup2(fd, 1);
    dup2(fd, 2);
    sdb_close(fd);
    fprintf(stderr,"--- sdb starting (pid %d) ---\n", getpid());
#endif
}

#if !SDB_HOST
void start_device_log(void)
{
    int fd;
    char    path[PATH_MAX];
    struct tm now;
    time_t t;
//    char value[PROPERTY_VALUE_MAX];
    const char* p = getenv("SDB_TRACE");
    // read the trace mask from persistent property persist.sdb.trace_mask
    // give up if the property is not set or cannot be parsed
#if 0 /* tizen specific */
    property_get("persist.sdb.trace_mask", value, "");
    if (sscanf(value, "%x", &sdb_trace_mask) != 1)
        return;
#endif

    if (p == NULL) {
        return;
    }
    tzset();
    time(&t);
    localtime_r(&t, &now);
    strftime(path, sizeof(path),
                "/tmp/sdbd-%Y-%m-%d-%H-%M-%S.txt",
                &now);
    fd = unix_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        return;
    }

    // redirect stdout and stderr to the log file
    dup2(fd, 1);
    dup2(fd, 2);
    fprintf(stderr,"--- sdbd starting (pid %d) ---\n", getpid());
    sdb_close(fd);

    fd = unix_open("/dev/null", O_RDONLY);
    if (fd < 0) {
        // hopefully not gonna happen
        return;
    }
    dup2(fd, 0);
    sdb_close(fd);
}

int daemonize(void) {

    // set file creation mask to 0
    umask(0);

    switch (fork()) {
    case -1:
        return -1;
    case 0:
        break;
    default:
        _exit(0);
    }
#ifdef SDB_PIDPATH
    FILE *f = fopen(SDB_PIDPATH, "w");

    if (f != NULL) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
#endif
    if (setsid() == -1)
        return -1;

    if (chdir("/") < 0)
        D("sdbd: unable to change working directory to /\n");

    return 0;
}
#endif

#if SDB_HOST
int launch_server(int server_port)
{
#ifdef HAVE_WIN32_PROC
    /* we need to start the server in the background                    */
    /* we create a PIPE that will be used to wait for the server's "OK" */
    /* message since the pipe handles must be inheritable, we use a     */
    /* security attribute                                               */
    HANDLE                pipe_read, pipe_write;
    SECURITY_ATTRIBUTES   sa;
    STARTUPINFO           startup;
    PROCESS_INFORMATION   pinfo;
    char                  program_path[ MAX_PATH ];
    int                   ret;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    /* create pipe, and ensure its read handle isn't inheritable */
    ret = CreatePipe( &pipe_read, &pipe_write, &sa, 0 );
    if (!ret) {
        fprintf(stderr, "CreatePipe() failure, error %ld\n", GetLastError() );
        return -1;
    }

    SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );

    ZeroMemory( &startup, sizeof(startup) );
    startup.cb = sizeof(startup);
    startup.hStdInput  = GetStdHandle( STD_INPUT_HANDLE );
    startup.hStdOutput = pipe_write;
    startup.hStdError  = GetStdHandle( STD_ERROR_HANDLE );
    startup.dwFlags    = STARTF_USESTDHANDLES;

    ZeroMemory( &pinfo, sizeof(pinfo) );

    /* get path of current program */
    GetModuleFileName( NULL, program_path, sizeof(program_path) );

    ret = CreateProcess(
            program_path,                              /* program path  */
            "sdb fork-server server",
                                    /* the fork-server argument will set the
                                       debug = 2 in the child           */
            NULL,                   /* process handle is not inheritable */
            NULL,                    /* thread handle is not inheritable */
            TRUE,                          /* yes, inherit some handles */
            DETACHED_PROCESS, /* the new process doesn't have a console */
            NULL,                     /* use parent's environment block */
            NULL,                    /* use parent's starting directory */
            &startup,                 /* startup info, i.e. std handles */
            &pinfo );

    CloseHandle( pipe_write );

    if (!ret) {
        fprintf(stderr, "CreateProcess failure, error %ld\n", GetLastError() );
        CloseHandle( pipe_read );
        return -1;
    }

    CloseHandle( pinfo.hProcess );
    CloseHandle( pinfo.hThread );

    /* wait for the "OK\n" message */
    {
        char  temp[3];
        DWORD  count;

        ret = ReadFile( pipe_read, temp, 3, &count, NULL );
        CloseHandle( pipe_read );
        if ( !ret ) {
            fprintf(stderr, "could not read ok from SDB Server, error = %ld\n", GetLastError() );
            return -1;
        }
        if (count != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "SDB server didn't ACK\n" );
            return -1;
        }
    }
#elif defined(HAVE_FORKEXEC)
    char    path[PATH_MAX];
    int     fd[2];

    // set up a pipe so the child can tell us when it is ready.
    // fd[0] will be parent's end, and fd[1] will get mapped to stderr in the child.
    if (pipe(fd)) {
        fprintf(stderr, "pipe failed in launch_server, errno: %d\n", errno);
        return -1;
    }
    get_my_path(path, PATH_MAX);
    pid_t pid = fork();
    if(pid < 0) return -1;

    if (pid == 0) {
        // child side of the fork

        // redirect stderr to the pipe
        // we use stderr instead of stdout due to stdout's buffering behavior.
        sdb_close(fd[0]);
        dup2(fd[1], STDERR_FILENO);
        sdb_close(fd[1]);

        // child process
        int result = execl(path, "sdb", "fork-server", "server", NULL);
        // this should not return
        fprintf(stderr, "OOPS! execl returned %d, errno: %d\n", result, errno);
    } else  {
        // parent side of the fork

        char  temp[3];

        temp[0] = 'A'; temp[1] = 'B'; temp[2] = 'C';
        // wait for the "OK\n" message
        sdb_close(fd[1]);
        int ret = sdb_read(fd[0], temp, 3);
        int saved_errno = errno;
        sdb_close(fd[0]);
        if (ret < 0) {
            fprintf(stderr, "could not read ok from SDB Server, errno = %d\n", saved_errno);
            return -1;
        }
        if (ret != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "SDB server didn't ACK\n" );
            return -1;
        }

        setsid();
    }
#else
#error "cannot implement background server start on this platform"
#endif
    return 0;
}
#endif

/* Constructs a local name of form tcp:port.
 * target_str points to the target string, it's content will be overwritten.
 * target_size is the capacity of the target string.
 * server_port is the port number to use for the local name.
 */
void build_local_name(char* target_str, size_t target_size, int server_port)
{
  snprintf(target_str, target_size, "tcp:%d", server_port);
}

#if !SDB_HOST
static void init_drop_privileges() {
#ifdef _DROP_PRIVILEGE
    rootshell_mode = 0;
#else
    rootshell_mode = 1;
#endif
}

int should_drop_privileges() {
    if (rootshell_mode == 1) { // if root, then don't drop
        return 0;
    }
    return 1;
}

int set_developer_privileges() {
    gid_t groups[] = { SID_DEVELOPER, SID_APP_LOGGING, SID_SYS_LOGGING, SID_INPUT };
    if (setgroups(sizeof(groups) / sizeof(groups[0]), groups) != 0) {
        fprintf(stderr, "set groups failed (errno: %d, %s)\n", errno, strerror(errno));
        //exit(1);
    }

    // then switch user and group to developer
    if (setgid(SID_DEVELOPER) != 0) {
        fprintf(stderr, "set group id failed (errno: %d, %s)\n", errno, strerror(errno));
        //exit(1);
        return -1;
    }

    if (setuid(SID_DEVELOPER) != 0) {
        fprintf(stderr, "set user id failed (errno: %d, %s)\n", errno, strerror(errno));
        //exit(1);
        return -1;
    }

    if (chdir("/home/developer") < 0) {
        D("sdbd: unable to change working directory to /home/developer\n");
    } else {
        if (chdir("/") < 0) {
            D("sdbd: unable to change working directory to /\n");
        }
    }
    return 1;
}
#define ONDEMAND_ROOT_PATH "/home/developer"

static void init_sdk_requirements() {
    struct stat st;

    if (!getenv("TERM")) {
        putenv("TERM=linux");
    }

    if (stat(ONDEMAND_ROOT_PATH, &st) == -1) {
        return;
    }
    if (st.st_uid != SID_DEVELOPER || st.st_gid != SID_DEVELOPER) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "chown developer:developer %s -R", ONDEMAND_ROOT_PATH);
        if (system(cmd) < 0) {
            D("failed to change ownership to developer to %s\n", ONDEMAND_ROOT_PATH);
        }
    }
}
#endif /* !SDB_HOST */

int sdb_main(int is_daemon, int server_port)
{
#if !SDB_HOST

    init_drop_privileges();
    init_sdk_requirements();
    umask(000);
#endif

    atexit(sdb_cleanup);
#ifdef HAVE_WIN32_PROC
    SetConsoleCtrlHandler( ctrlc_handler, TRUE );
#elif defined(HAVE_FORKEXEC)
    // No SIGCHLD. Let the service subproc handle its children.
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();


#if SDB_HOST
    HOST = 1;
    usb_vendors_init();
    usb_init();
    local_init(DEFAULT_SDB_LOCAL_TRANSPORT_PORT);

    char local_name[30];
    build_local_name(local_name, sizeof(local_name), server_port);
    if(install_listener(local_name, "*smartsocket*", NULL)) {
        exit(1);
    }
#else
    /* don't listen on a port (default 5037) if running in secure mode */
    /* don't run as root if we are running in secure mode */

    if (should_drop_privileges()) {
# if 0
        struct __user_cap_header_struct header;
        struct __user_cap_data_struct cap;

        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
            exit(1);
        }
        /* add extra groups:
        ** SID_TTY to access /dev/ptmx
        */
        gid_t groups[] = { SID_TTY, SID_APP_LOGGING, SID_SYS_LOGGING };
        if (setgroups(sizeof(groups)/sizeof(groups[0]), groups) != 0) {
            exit(1);
        }
        /* then switch user and group to "developer" */
        if (setgid(SID_DEVELOPER) != 0) {
            fprintf(stderr, "set group id failed errno: %d\n", errno);
            exit(1);
        }
        if (setuid(SID_DEVELOPER) != 0) {
            fprintf(stderr, "set user id failed errno: %d\n", errno);
            exit(1);
        }

        /* set CAP_SYS_BOOT capability, so "sdb reboot" will succeed */
        header.version = _LINUX_CAPABILITY_VERSION;
        header.pid = 0;
        cap.effective = cap.permitted = (1 << CAP_SYS_BOOT);
        cap.inheritable = 0;
        capset(&header, &cap);
#endif
        D("Local port disabled\n");
    } else {
        char local_name[30];
        build_local_name(local_name, sizeof(local_name), server_port);
        if(install_listener(local_name, "*smartsocket*", NULL)) {
            exit(1);
        }
    }

    if (access("/dev/samsung_sdb", F_OK) == 0) {
        // listen on USB
        usb_init();
        // listen on tcp
        //local_init(DEFAULT_SDB_LOCAL_TRANSPORT_PORT);
    } else {
        // listen on default port
        local_init(DEFAULT_SDB_LOCAL_TRANSPORT_PORT);
    }

#if 0 /* tizen specific */
    D("sdb_main(): pre init_jdwp()\n");
    init_jdwp();
    D("sdb_main(): post init_jdwp()\n");
#endif
#endif

    if (is_daemon)
    {
        // inform our parent that we are up and running.
#ifdef HAVE_WIN32_PROC
        DWORD  count;
        WriteFile( GetStdHandle( STD_OUTPUT_HANDLE ), "OK\n", 3, &count, NULL );
#elif defined(HAVE_FORKEXEC)
        fprintf(stderr, "OK\n");
#endif
        start_logging();
    }
    D("Event loop starting\n");

    fdevent_loop();

    usb_cleanup();

    return 0;
}

#if SDB_HOST
void connect_device(char* host, char* buffer, int buffer_size)
{
    int port, fd;
    char* portstr = strchr(host, ':');
    char hostbuf[100];
    char serial[100];

    strncpy(hostbuf, host, sizeof(hostbuf) - 1);
    if (portstr) {
        if (portstr - host >= sizeof(hostbuf)) {
            snprintf(buffer, buffer_size, "bad host name %s", host);
            return;
        }
        // zero terminate the host at the point we found the colon
        hostbuf[portstr - host] = 0;
        if (sscanf(portstr + 1, "%d", &port) == 0) {
            snprintf(buffer, buffer_size, "bad port number %s", portstr);
            return;
        }
    } else {
        port = DEFAULT_SDB_LOCAL_TRANSPORT_PORT;
    }

    snprintf(serial, sizeof(serial), "%s:%d", hostbuf, port);
    if (find_transport(serial)) {
        snprintf(buffer, buffer_size, "already connected to %s", serial);
        return;
    }

    fd = socket_network_client(hostbuf, port, SOCK_STREAM);
    if (fd < 0) {
        snprintf(buffer, buffer_size, "unable to connect to %s", host);
        return;
    }

    D("client: connected on remote on fd %d\n", fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);
    register_socket_transport(fd, serial, port, 0, NULL);
    snprintf(buffer, buffer_size, "connected to %s", serial);
}

void connect_emulator(char* port_spec, char* buffer, int buffer_size)
{
    char* port_separator = strchr(port_spec, ',');
    if (!port_separator) {
        snprintf(buffer, buffer_size,
                "unable to parse '%s' as <console port>,<sdb port>",
                port_spec);
        return;
    }

    // Zero-terminate console port and make port_separator point to 2nd port.
    *port_separator++ = 0;
    int console_port = strtol(port_spec, NULL, 0);
    int sdb_port = strtol(port_separator, NULL, 0);
    if (!(console_port > 0 && sdb_port > 0)) {
        *(port_separator - 1) = ',';
        snprintf(buffer, buffer_size,
                "Invalid port numbers: Expected positive numbers, got '%s'",
                port_spec);
        return;
    }

    /* Check if the emulator is already known.
     * Note: There's a small but harmless race condition here: An emulator not
     * present just yet could be registered by another invocation right
     * after doing this check here. However, local_connect protects
     * against double-registration too. From here, a better error message
     * can be produced. In the case of the race condition, the very specific
     * error message won't be shown, but the data doesn't get corrupted. */
    atransport* known_emulator = find_emulator_transport_by_sdb_port(sdb_port);
    if (known_emulator != NULL) {
        snprintf(buffer, buffer_size,
                "Emulator on port %d already registered.", sdb_port);
        return;
    }

    /* Check if more emulators can be registered. Similar unproblematic
     * race condition as above. */
    int candidate_slot = get_available_local_transport_index();
    if (candidate_slot < 0) {
        snprintf(buffer, buffer_size, "Cannot accept more emulators.");
        return;
    }

    /* Preconditions met, try to connect to the emulator. */
    if (!local_connect_arbitrary_ports(console_port, sdb_port, NULL)) {
        snprintf(buffer, buffer_size,
                "Connected to emulator on ports %d,%d", console_port, sdb_port);
    } else {
        snprintf(buffer, buffer_size,
                "Could not connect to emulator on ports %d,%d",
                console_port, sdb_port);
    }
}
#endif

int handle_host_request(char *service, transport_type ttype, char* serial, int reply_fd, asocket *s)
{
    atransport *transport = NULL;
    char buf[4096];

    if(!strcmp(service, "kill")) {
        fprintf(stderr,"sdb server killed by remote request\n");
        fflush(stdout);
        sdb_write(reply_fd, "OKAY", 4);
        usb_cleanup();
        exit(0);
    }

#if SDB_HOST
    // "transport:" is used for switching transport with a specified serial number
    // "transport-usb:" is used for switching transport to the only USB transport
    // "transport-local:" is used for switching transport to the only local transport
    // "transport-any:" is used for switching transport to the only transport
    if (!strncmp(service, "transport", strlen("transport"))) {
        char* error_string = "unknown failure";
        transport_type type = kTransportAny;

        if (!strncmp(service, "transport-usb", strlen("transport-usb"))) {
            type = kTransportUsb;
        } else if (!strncmp(service, "transport-local", strlen("transport-local"))) {
            type = kTransportLocal;
        } else if (!strncmp(service, "transport-any", strlen("transport-any"))) {
            type = kTransportAny;
        } else if (!strncmp(service, "transport:", strlen("transport:"))) {
            service += strlen("transport:");
            serial = service;
        }

        transport = acquire_one_transport(CS_ANY, type, serial, &error_string);

        if (transport) {
            s->transport = transport;
            sdb_write(reply_fd, "OKAY", 4);
        } else {
            sendfailmsg(reply_fd, error_string);
        }
        return 1;
    }

    // return a list of all connected devices
    if (!strcmp(service, "devices")) {
        char buffer[4096];
        memset(buf, 0, sizeof(buf));
        memset(buffer, 0, sizeof(buffer));
        D("Getting device list \n");
        list_transports(buffer, sizeof(buffer));
        snprintf(buf, sizeof(buf), "OKAY%04x%s",(unsigned)strlen(buffer),buffer);
        D("Wrote device list \n");
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    // add a new TCP transport, device or emulator
    if (!strncmp(service, "connect:", 8)) {
        char buffer[4096];
        char* host = service + 8;
        if (!strncmp(host, "emu:", 4)) {
            connect_emulator(host + 4, buffer, sizeof(buffer));
        } else {
            connect_device(host, buffer, sizeof(buffer));
        }
        // Send response for emulator and device
        snprintf(buf, sizeof(buf), "OKAY%04x%s",(unsigned)strlen(buffer), buffer);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    // remove TCP transport
    if (!strncmp(service, "disconnect:", 11)) {
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        char* serial = service + 11;
        if (serial[0] == 0) {
            // disconnect from all TCP devices
            unregister_all_tcp_transports();
        } else {
            char hostbuf[100];
            // assume port 26101 if no port is specified
            if (!strchr(serial, ':')) {
                snprintf(hostbuf, sizeof(hostbuf) - 1, "%s:26101", serial);
                serial = hostbuf;
            }
            atransport *t = find_transport(serial);

            if (t) {
                unregister_transport(t);
            } else {
                snprintf(buffer, sizeof(buffer), "No such device %s", serial);
            }
        }

        snprintf(buf, sizeof(buf), "OKAY%04x%s",(unsigned)strlen(buffer), buffer);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    // returns our value for SDB_SERVER_VERSION
    if (!strcmp(service, "version")) {
        char version[12];
        snprintf(version, sizeof version, "%04x", SDB_SERVER_VERSION);
        snprintf(buf, sizeof buf, "OKAY%04x%s", (unsigned)strlen(version), version);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    if(!strncmp(service,"get-serialno",strlen("get-serialno"))) {
        char *out = "unknown";
         transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
       if (transport && transport->serial) {
            out = transport->serial;
        }
        snprintf(buf, sizeof buf, "OKAY%04x%s",(unsigned)strlen(out),out);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }
    // indicates a new emulator instance has started
       if (!strncmp(service,"emulator:",9)) { /* tizen specific */
           char *tmp = strtok(service+9, DEVICEMAP_SEPARATOR);
           int  port = 0;

           if (tmp == NULL) {
               port = atoi(service+9);
           } else {
               port = atoi(tmp);
               tmp = strtok(NULL, DEVICEMAP_SEPARATOR);
               if (tmp != NULL) {
                   local_connect(port, tmp);
               }
           }
           local_connect(port, NULL);
        return 0;
    }
#endif // SDB_HOST

    if(!strncmp(service,"forward:",8) || !strncmp(service,"killforward:",12)) {
        char *local, *remote, *err;
        int r;
        atransport *transport;

        int createForward = strncmp(service,"kill",4);

        local = service + (createForward ? 8 : 12);
        remote = strchr(local,';');
        if(remote == 0) {
            sendfailmsg(reply_fd, "malformed forward spec");
            return 0;
        }

        *remote++ = 0;
        if((local[0] == 0) || (remote[0] == 0) || (remote[0] == '*')){
            sendfailmsg(reply_fd, "malformed forward spec");
            return 0;
        }

        transport = acquire_one_transport(CS_ANY, ttype, serial, &err);
        if (!transport) {
            sendfailmsg(reply_fd, err);
            return 0;
        }

        if (createForward) {
            r = install_listener(local, remote, transport);
        } else {
            r = remove_listener(local, remote, transport);
        }
        if(r == 0) {
                /* 1st OKAY is connect, 2nd OKAY is status */
            writex(reply_fd, "OKAYOKAY", 8);
            return 0;
        }

        if (createForward) {
            sendfailmsg(reply_fd, (r == -1) ? "cannot rebind smartsocket" : "cannot bind socket");
        } else {
            sendfailmsg(reply_fd, "cannot remove listener");
        }
        return 0;
    }

    if(!strncmp(service,"get-state",strlen("get-state"))) {
        transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
        char *state = connection_state_name(transport);
        snprintf(buf, sizeof buf, "OKAY%04x%s",(unsigned)strlen(state),state);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }
    return -1;
}

#if !SDB_HOST
int recovery_mode = 0;
#endif

int main(int argc, char **argv)
{
    sdb_trace_init(); /* tizen specific */
#if SDB_HOST
    sdb_sysdeps_init();
    sdb_trace_init();
    return sdb_commandline(argc - 1, argv + 1);
#else
    /* If sdbd runs inside the emulator this will enable sdb tracing via
     * sdb-debug qemud service in the emulator. */
#if 0 /* tizen specific */
    sdb_qemu_trace_init();
    if((argc > 1) && (!strcmp(argv[1],"recovery"))) {
        sdb_device_banner = "recovery";
        recovery_mode = 1;
    }
#endif
#if !SDB_HOST
    if (daemonize() < 0)
        fatal("daemonize() failed: %.200s", strerror(errno));
#endif

    start_device_log();
    D("Handling main()\n");

    //sdbd will never die on emulator!
    signal(SIGTERM, handle_sig_term); /* tizen specific */
    return sdb_main(0, DEFAULT_SDB_PORT);
#endif
}
