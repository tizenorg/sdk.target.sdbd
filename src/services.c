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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <grp.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "sdb.h"
#include "file_sync_service.h"

#if SDB_HOST
#  ifndef HAVE_WINSOCK
#    include <netinet/in.h>
#    include <netdb.h>
#    include <sys/ioctl.h>
#  endif
#else
#   include <sys/inotify.h>
#   include "sdktools.h"
#endif

#include "strutils.h"
#include <system_info_internal.h>
#include <vconf.h>
#include <limits.h>

typedef struct stinfo stinfo;

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};


void *service_bootstrap_func(void *x)
{
    stinfo *sti = x;
    sti->func(sti->fd, sti->cookie);
    free(sti);
    return 0;
}

#if SDB_HOST
SDB_MUTEX_DEFINE( dns_lock );

static void dns_service(int fd, void *cookie)
{
    char *hostname = cookie;
    struct hostent *hp;
    unsigned zero = 0;

    sdb_mutex_lock(&dns_lock);
    hp = gethostbyname(hostname);
    free(cookie);
    if(hp == 0) {
        writex(fd, &zero, 4);
    } else {
        writex(fd, hp->h_addr, 4);
    }
    sdb_mutex_unlock(&dns_lock);
    sdb_close(fd);
}
#else

#if 0
extern int recovery_mode;

static void recover_service(int s, void *cookie)
{
    unsigned char buf[4096];
    unsigned count = (unsigned) cookie;
    int fd;

    fd = sdb_creat("/tmp/update", 0644);
    if(fd < 0) {
        sdb_close(s);
        return;
    }

    while(count > 0) {
        unsigned xfer = (count > 4096) ? 4096 : count;
        if(readx(s, buf, xfer)) break;
        if(writex(fd, buf, xfer)) break;
        count -= xfer;
    }

    if(count == 0) {
        writex(s, "OKAY", 4);
    } else {
        writex(s, "FAIL", 4);
    }
    sdb_close(fd);
    sdb_close(s);

    fd = sdb_creat("/tmp/update.begin", 0644);
    sdb_close(fd);
}

void restart_root_service(int fd, void *cookie)
{
    char buf[100];
    char value[PROPERTY_VALUE_MAX];

    if (getuid() == 0) {
        snprintf(buf, sizeof(buf), "sdbd is already running as root\n");
        writex(fd, buf, strlen(buf));
        sdb_close(fd);
    } else {
        property_get("ro.debuggable", value, "");
        if (strcmp(value, "1") != 0) {
            snprintf(buf, sizeof(buf), "sdbd cannot run as root in production builds\n");
            writex(fd, buf, strlen(buf));
            sdb_close(fd);
            return;
        }

        property_set("service.sdb.root", "1");
        snprintf(buf, sizeof(buf), "restarting sdbd as root\n");
        writex(fd, buf, strlen(buf));
        sdb_close(fd);
    }
}
#endif

void rootshell_service(int fd, void *cookie)
{
    char buf[100];
    char *mode = (char*) cookie;

    if (!strcmp(mode, "on")) {
        if (rootshell_mode == 1) {
            //snprintf(buf, sizeof(buf), "Already changed to developer mode\n");
            // do not show message
        } else {
            if (access("/bin/su", F_OK) == 0) {
                rootshell_mode = 1;
                //allows a permitted user to execute a command as the superuser
                snprintf(buf, sizeof(buf), "Switched to 'root' account mode\n");
            } else {
                snprintf(buf, sizeof(buf), "Permission denied\n");
            }
            writex(fd, buf, strlen(buf));
        }
    } else if (!strcmp(mode, "off")) {
        if (rootshell_mode == 1) {
            rootshell_mode = 0;
            snprintf(buf, sizeof(buf), "Switched to 'developer' account mode\n");
            writex(fd, buf, strlen(buf));
        }
    } else {
        snprintf(buf, sizeof(buf), "Unknown command option\n");
        writex(fd, buf, strlen(buf));
    }
    D("set rootshell to %s\n", rootshell_mode == 1 ? "root" : "developer");
    free(mode);
    sdb_close(fd);
}

void reboot_service(int fd, void *arg)
{
#if 0
    char buf[100];
    int pid, ret;

    sync();

    /* Attempt to unmount the SD card first.
     * No need to bother checking for errors.
     */
    pid = fork();
    if (pid == 0) {
        /* ask vdc to unmount it */
        // prevent: Use of untrusted string value (TAINTED_STRING)
        execl("/system/bin/vdc", "/system/bin/vdc", "volume", "unmount",
                getenv("EXTERNAL_STORAGE"), "force", NULL);
    } else if (pid > 0) {
        /* wait until vdc succeeds or fails */
        waitpid(pid, &ret, 0);
    }

    ret = android_reboot(ANDROID_RB_RESTART2, 0, (char *) arg);
    if (ret < 0) {
        snprintf(buf, sizeof(buf), "reboot failed: %s\n", strerror(errno));
        writex(fd, buf, strlen(buf));
    }
    free(arg);
    sdb_close(fd);
#endif
}

#if !SDB_HOST
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#define CS_PATH     "/opt/usr/share/crash/report"

void inoti_service(int fd, void *arg)
{
    int wd;
    int ifd;
    char buffer[BUF_LEN];

    D( "inoti_service start\n");
    ifd = inotify_init();

    if ( ifd < 0 ) {
        D( "inotify_init failed\n");
        return;
    }

    wd = inotify_add_watch( ifd, CS_PATH, IN_CREATE);

    for ( ; ; ) {
        int length, i = 0;
        length = sdb_read( ifd, buffer, BUF_LEN );

        if ( length < 0 ) {
            D( "inoti read failed\n");
            goto done;
        }

        while ( i >= 0 && i < length ) {
            struct inotify_event *event = ( struct inotify_event * )&buffer[i];
            if (event->len) {
                if ( event->mask & IN_CREATE) {
                    if (!(event->mask & IN_ISDIR)) {
                        char *cspath = NULL;
                        int len = asprintf(&cspath, "%s/%s", CS_PATH, event->name);
                        D( "The file %s was created.\n", cspath);
                        writex(fd, cspath, len);
                        if (cspath != NULL) {
                            free(cspath);
                        }
                    }
                }
            }
            if (i + EVENT_SIZE + event->len > INT_MAX ) { // in case of integer is max
                break;
            }
            i += EVENT_SIZE + event->len;
        }
    }

done:
    inotify_rm_watch( ifd, wd );
    sdb_close(ifd);
    sdb_close(fd);
    D( "inoti_service end\n");
}
#endif
#endif

void rndis_config_service(int fd, void *cookie)
{
    char buf[100];
    int val = 0;
    char* mode = (char*) cookie;

    usb_mode = 0;
    if (vconf_get_int(DEBUG_MODE_KEY, &val)) {
        D("Failed to get debug mode\n");
        sdb_close(fd);
        free(mode);
        return;
    }
    if (!strcmp(mode, "on")) {
        if (val != 6) {
            usb_mode = 6;
            sdb_sleep_ms(500);
            if (vconf_set_int(DEBUG_MODE_KEY, 6)) {
                D("Failed to set rndis %s\n", mode);
                snprintf(buf, sizeof(buf), "Failed to set rndis %s\n", mode);
                writex(fd, buf, strlen(buf));
            }
        }
    } else if (!strcmp(mode, "off")) {
        if (val != 2) {
            usb_mode = 2;
            sdb_sleep_ms(500);
            if (vconf_set_int(DEBUG_MODE_KEY, 2)) {
                D("Failed to set rndis %s\n", mode);
                snprintf(buf, sizeof(buf), "Failed to set rndis %s\n", mode);
                writex(fd, buf, strlen(buf));
            }
        }
    } else {
        D("Unknown command option:(rndis %s)\n", mode);
        snprintf(buf, sizeof(buf), "Unknown command option:(rndis %s)\n", mode);
        writex(fd, buf, strlen(buf));
    }
    free(mode);
    sdb_close(fd);
}

#if 0
static void echo_service(int fd, void *cookie)
{
    char buf[4096];
    int r;
    char *p;
    int c;

    for(;;) {
        r = read(fd, buf, 4096);
        if(r == 0) goto done;
        if(r < 0) {
            if(errno == EINTR) continue;
            else goto done;
        }

        c = r;
        p = buf;
        while(c > 0) {
            r = write(fd, p, c);
            if(r > 0) {
                c -= r;
                p += r;
                continue;
            }
            if((r < 0) && (errno == EINTR)) continue;
            goto done;
        }
    }
done:
    close(fd);
}
#endif

static int create_service_thread(void (*func)(int, void *), void *cookie)
{
    stinfo *sti;
    sdb_thread_t t;
    int s[2];

    if(sdb_socketpair(s)) {
        D("cannot create service socket pair\n");
        return -1;
    }

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = func;
    sti->cookie = cookie;
    sti->fd = s[1];

    if(sdb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        sdb_close(s[0]);
        sdb_close(s[1]);
        D("cannot create service thread\n");
        return -1;
    }

    D("service thread started, %d:%d\n",s[0], s[1]);
    return s[0];
}

#if !SDB_HOST

static int create_subprocess(const char *cmd, pid_t *pid, const char *argv[], const char *envp[])
{
    char *devname;
    int ptm;

    ptm = unix_open("/dev/ptmx", O_RDWR); // | O_NOCTTY);
    if(ptm < 0){
        D("[ cannot open /dev/ptmx - %s ]\n",strerror(errno));
        return -1;
    }
    if (fcntl(ptm, F_SETFD, FD_CLOEXEC) < 0) {
        D("[ cannot set cloexec to /dev/ptmx - %s ]\n",strerror(errno));
    }

    if(grantpt(ptm) || unlockpt(ptm) ||
       ((devname = (char*) ptsname(ptm)) == 0)){
        D("[ trouble with /dev/ptmx - %s ]\n", strerror(errno));
        sdb_close(ptm);
        return -1;
    }

    *pid = fork();
    if(*pid < 0) {
        D("- fork failed: %s -\n", strerror(errno));
        sdb_close(ptm);
        return -1;
    }

    if(*pid == 0){
        int pts;

        setsid();

        pts = unix_open(devname, O_RDWR);
        if(pts < 0) {
            fprintf(stderr, "child failed to open pseudo-term slave: %s\n", devname);
            exit(-1);
        }

        dup2(pts, 0);
        dup2(pts, 1);
        dup2(pts, 2);

        sdb_close(pts);
        sdb_close(ptm);

        // set OOM adjustment to zero
        {
            char text[64];
            snprintf(text, sizeof text, "/proc/%d/oom_adj", getpid());
            int fd = sdb_open(text, O_WRONLY);
            if (fd >= 0) {
                sdb_write(fd, "0", 1);
                sdb_close(fd);
            } else {
               // FIXME: not supposed to be here
               D("sdb: unable to open %s due to %s\n", text, strerror(errno));
            }
        }

        if (should_drop_privileges()) {
            if (argv[2] != NULL && verify_root_commands(argv[2])) {
                // do nothing
                D("sdb: executes root commands!!:%s\n", argv[2]);
            } else {
                set_developer_privileges();
            }
        }

        execve(cmd, argv, envp);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        // Don't set child's OOM adjustment to zero.
        // Let the child do it itself, as sometimes the parent starts
        // running before the child has a /proc/pid/oom_adj.
        // """sdb: unable to open /proc/644/oom_adj""" seen in some logs.
        return ptm;
    }
}
#endif  /* !SDB_HOST */

#define SHELL_COMMAND "/bin/sh"
#define LOGIN_COMMAND "/bin/login"
#define SDK_USER      "developer"
#define SUPER_USER    "root"
#define LOGIN_CONFIG  "/etc/login.defs"

#if !SDB_HOST
static void subproc_waiter_service(int fd, void *cookie)
{
    pid_t pid = (pid_t)cookie;

    D("entered. fd=%d of pid=%d\n", fd, pid);
    for (;;) {
        int status;
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            D("fd=%d, post waitpid(pid=%d) status=%04x\n", fd, p, status);
            
            if (WIFEXITED(status)) {
                D("*** Exit code %d\n", WEXITSTATUS(status));
                break;
            } else if (WIFSIGNALED(status)) {
                D("*** Killed by signal %d\n", WTERMSIG(status));
                break;
            } else {
                D("*** Killed by unknown code %d\n", status);
                break;
            }
         }
    }
    D("shell exited fd=%d of pid=%d err=%d\n", fd, pid, errno);
    if (SHELL_EXIT_NOTIFY_FD >=0) {
      int res;
      res = writex(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd));
      D("notified shell exit via fd=%d for pid=%d res=%d errno=%d\n",
        SHELL_EXIT_NOTIFY_FD, pid, res, errno);
    }
}

static void get_env(char *key, char **env)
{
    FILE *fp;
    char buf[1024];
    int i;
    char *s, *e, *value;

    fp = fopen (LOGIN_CONFIG, "r");
    if (NULL == fp) {
        return;
    }

    while (fgets(buf, (int) sizeof (buf), fp) != NULL) {
        s = buf;
        e = buf + (strlen(buf) - 1);

        while(*e == ' ' ||  *e == '\n' || *e == '\t') {
            e--;
        }
        *(e+1) ='\0';

        while(*s != '\0' && (*s == ' ' || *s == '\t' || *s == '\n')) {
            s++;
        }

        if (*s == '#' || *s == '\0') {
            continue;
        }
        value = s + strcspn(s, " \t");
        *value++ = '\0';

        if(!strcmp(buf, key)) {
            *env = value;
            break;
        }
    }

    fclose(fp);
}

static int create_subproc_thread(const char *name)
{
    stinfo *sti;
    sdb_thread_t t;
    int ret_fd;
    pid_t pid;
    char *value = NULL;

    char *envp[] = {
        "TERM=linux", /* without this, some programs based on screen can't work, e.g. top */
        "DISPLAY=:0", /* without this, some programs based on without launchpad can't work */
        NULL,
        NULL,
        NULL
    };
    if (should_drop_privileges()) {
        envp[2] = "HOME=/home/developer";
        get_env("ENV_PATH", &value);
    } else {
        get_env("ENV_SUPATH", &value);
        envp[2] = "HOME=/root";
    }
    if (value != NULL) {
        envp[3] = value;
    }

    D("path env:%s,%s,%s,%s\n", envp[0], envp[1], envp[2], envp[3]);

    if(name) { // in case of shell execution directly
        char *args[] = {
            SHELL_COMMAND,
            "-c",
            NULL,
            "-l",
            SUPER_USER,
            NULL,
        };
        args[2] = name;

        ret_fd = create_subprocess(SHELL_COMMAND, &pid, args, envp);
    } else { // in case of shell interactively
        char *args[] = {
                SHELL_COMMAND,
                "-",
                NULL,
        };
        ret_fd = create_subprocess(SHELL_COMMAND, &pid, args, envp);
#if 0   // FIXME: should call login command instead of /bin/sh
        if (should_drop_privileges()) {
            char *args[] = {
                SHELL_COMMAND,
                "-",
                NULL,
            };
            ret_fd = create_subprocess(SHELL_COMMAND, &pid, args, envp);
        } else {
            char *args[] = {
                LOGIN_COMMAND,
                "-f",
                SUPER_USER,
                NULL,
            };
            ret_fd = create_subprocess(LOGIN_COMMAND, &pid, args, envp);
        }
#endif
    }
    D("create_subprocess() ret_fd=%d pid=%d\n", ret_fd, pid);

    if (ret_fd < 0) {
        D("cannot create service thread\n");
        return -1;
    }
    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*)pid;
    sti->fd = ret_fd;

    if(sdb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        sdb_close(ret_fd);
        D("cannot create service thread\n");
        return -1;
    }

    D("service thread started, fd=%d pid=%d\n",ret_fd, pid);
    return ret_fd;
}

static int create_sync_subprocess(void (*func)(int, void *), void* cookie) {
    stinfo *sti;
    sdb_thread_t t;
    int s[2];

    if(sdb_socketpair(s)) {
        D("cannot create service socket pair\n");
        return -1;
    }

    pid_t pid = fork();

    if (pid == 0) {
        sdb_close(s[0]);
        func(s[1], cookie);
        exit(-1);
    } else if (pid > 0) {
        sdb_close(s[1]);
        // FIXME: do not wait child process hear
        //waitpid(pid, &ret, 0);
    }
    if (pid < 0) {
        D("- fork failed: %s -\n", strerror(errno));
        sdb_close(s[0]);
        sdb_close(s[1]);
        D("cannot create sync service sub process\n");
        return -1;
    }

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*)pid;
    sti->fd = s[0];

    if(sdb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        sdb_close(s[0]);
        sdb_close(s[1]);
        printf("cannot create service monitor thread\n");
        return -1;
    }

    D("service process started, fd=%d pid=%d\n",s[0], pid);
    return s[0];
}

static int create_syncproc_thread()
{
    int ret_fd;

    ret_fd = create_sync_subprocess(file_sync_service, NULL);
    // FIXME: file missing bug when root on mode
    /*
    if (should_drop_privileges()) {
        ret_fd = create_sync_subprocess(file_sync_service, NULL);
    } else {
        ret_fd = create_service_thread(file_sync_service, NULL);
    }
    */

    return ret_fd;
}

#endif

#define UNKNOWN "unknown"
#define INFOBUF_MAXLEN 64
#define INFO_VERSION "2.2.0"
typedef struct platform_info {
    
    char platform_info_version[INFOBUF_MAXLEN];
    char model_name[INFOBUF_MAXLEN]; // Emulator
    char platform_name[INFOBUF_MAXLEN]; // Tizen
    char platform_version[INFOBUF_MAXLEN]; // 2.2.1
    char profile_name[INFOBUF_MAXLEN]; // 2.2.1
} pinfo;

static void get_platforminfo(int fd, void *cookie) {
    pinfo sysinfo;

    char *value = NULL;
    s_strncpy(sysinfo.platform_info_version, INFO_VERSION, strlen(INFO_VERSION));

    int r = system_info_get_value_string(SYSTEM_INFO_KEY_MODEL, &value);
    if (r != SYSTEM_INFO_ERROR_NONE) {
        s_strncpy(sysinfo.model_name, UNKNOWN, strlen(UNKNOWN));
        D("fail to get system model:%d\n", errno);
    } else {
        s_strncpy(sysinfo.model_name, value, sizeof(sysinfo.model_name));
        D("returns model_name:%s\n", value);
        if (value != NULL) {
            free(value);
        }
    }

    r = system_info_get_value_string(SYSTEM_INFO_KEY_PLATFORM_NAME, &value);
    if (r != SYSTEM_INFO_ERROR_NONE) {
        s_strncpy(sysinfo.platform_name, UNKNOWN, strlen(UNKNOWN));
        D("fail to get platform name:%d\n", errno);
    } else {
        s_strncpy(sysinfo.platform_name, value, sizeof(sysinfo.platform_name));
        D("returns platform_name:%s\n", value);
        if (value != NULL) {
            free(value);
        }

    }

    // FIXME: the result is different when using SYSTEM_INFO_KEY_TIZEN_VERSION_NAME
    r = system_info_get_platform_string("tizen.org/feature/platform.version", &value);
    if (r != SYSTEM_INFO_ERROR_NONE) {
        s_strncpy(sysinfo.platform_version, UNKNOWN, strlen(UNKNOWN));
        D("fail to get platform version:%d\n", errno);
    } else {
        s_strncpy(sysinfo.platform_version, value, sizeof(sysinfo.platform_version));
        D("returns platform_version:%s\n", value);
        if (value != NULL) {
            free(value);
        }
    }

    r = system_info_get_platform_string("tizen.org/feature/profile", &value);
    if (r != SYSTEM_INFO_ERROR_NONE) {
        s_strncpy(sysinfo.profile_name, UNKNOWN, strlen(UNKNOWN));
        D("fail to get profile name:%d\n", errno);
    } else {
        s_strncpy(sysinfo.profile_name, value, sizeof(sysinfo.profile_name));
        D("returns profile name:%s\n", value);
        if (value != NULL) {
            free(value);
        }
    }

    writex(fd, &sysinfo, sizeof(pinfo));

    sdb_close(fd);
}

int service_to_fd(const char *name)
{
    int ret = -1;

    if(!strncmp(name, "tcp:", 4)) {
        int port = atoi(name + 4);
        name = strchr(name + 4, ':');
        if(name == 0) {
            if (is_emulator()){
                ret = socket_ifr_client(port , SOCK_STREAM, "eth0");
            } else {
                ret = socket_ifr_client(port , SOCK_STREAM, "usb0");
                if (ret < 0) {
                    if (ifconfig(SDB_FORWARD_IFNAME, SDB_FORWARD_INTERNAL_IP, SDB_FORWARD_INTERNAL_MASK, 1) == 0) {
                        ret = socket_ifr_client(port , SOCK_STREAM, SDB_FORWARD_IFNAME);
                    }
                }
            }
            if (ret < 0) {
                ret = socket_loopback_client(port, SOCK_STREAM);
            }
            if (ret >= 0) {
                disable_tcp_nagle(ret);
            }
        } else {
#if SDB_HOST
            sdb_mutex_lock(&dns_lock);
            ret = socket_network_client(name + 1, port, SOCK_STREAM);
            sdb_mutex_unlock(&dns_lock);
#else
            return -1;
#endif
        }
#ifndef HAVE_WINSOCK   /* winsock doesn't implement unix domain sockets */
    } else if(!strncmp(name, "local:", 6)) {
        ret = socket_local_client(name + 6,
                ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    } else if(!strncmp(name, "localreserved:", 14)) {
        ret = socket_local_client(name + 14,
                ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    } else if(!strncmp(name, "localabstract:", 14)) {
        ret = socket_local_client(name + 14,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localfilesystem:", 16)) {
        ret = socket_local_client(name + 16,
                ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
#endif
#if SDB_HOST
    } else if(!strncmp("dns:", name, 4)){
        char *n = strdup(name + 4);
        if(n == 0) return -1;
        ret = create_service_thread(dns_service, n);
#else /* !SDB_HOST */
    }/* else if(!strncmp("dev:", name, 4)) {// tizen specific
        ret = unix_open(name + 4, O_RDWR);
    } else if(!strncmp(name, "framebuffer:", 12)) {
        ret = create_service_thread(framebuffer_service, 0);
    } else if(recovery_mode && !strncmp(name, "recover:", 8)) {
        ret = create_service_thread(recover_service, (void*) atoi(name + 8));
    } else if (!strncmp(name, "jdwp:", 5)) {
        ret = create_jdwp_connection_fd(atoi(name+5));
    } else if (!strncmp(name, "log:", 4)) {
        ret = create_service_thread(log_service, get_log_file_path(name + 4));
    }*/ else if(!HOST && !strncmp(name, "shell:", 6)) {
        if(name[6]) {
            ret = create_subproc_thread(name + 6);
        } else {
            ret = create_subproc_thread(0);
        }
    } else if(!strncmp(name, "sync:", 5)) {
        //ret = create_service_thread(file_sync_service, NULL);
        ret = create_syncproc_thread();
    }/*  else if(!strncmp(name, "remount:", 8)) {
        ret = create_service_thread(remount_service, NULL);
    } else if(!strncmp(name, "reboot:", 7)) {
        void* arg = strdup(name + 7);
        if(arg == 0) return -1;
        ret = create_service_thread(reboot_service, arg);
    } else if(!strncmp(name, "root:", 5)) {
        ret = create_service_thread(restart_root_service, NULL);
    } else if(!strncmp(name, "backup:", 7)) {
        char* arg = strdup(name+7);
        if (arg == NULL) return -1;
        ret = backup_service(BACKUP, arg);
    } else if(!strncmp(name, "restore:", 8)) {
        ret = backup_service(RESTORE, NULL);
    }*/ else if(!strncmp(name, "root:", 5)) {
        char* service_name = NULL;

        service_name = strdup(name+5);
        ret = create_service_thread(rootshell_service, (void *)(service_name));
    } else if(!strncmp(name, "cs:", 5)) {
        ret = create_service_thread(inoti_service, NULL);
#endif
    } else if(!strncmp(name, "sysinfo:", 8)){
        ret = create_service_thread(get_platforminfo, 0);
    } else if(!strncmp(name, "rndis:", 6)){
        char *service_name = NULL;

        service_name = strdup(name+6);
        ret = create_service_thread(rndis_config_service, (void *)(service_name));
    }
    if (ret >= 0) {
        if (close_on_exec(ret) < 0) {
            D("failed to close fd exec\n");
        }
    }
    return ret;
}

#if SDB_HOST
struct state_info {
    transport_type transport;
    char* serial;
    int state;
};

static void wait_for_state(int fd, void* cookie)
{
    struct state_info* sinfo = cookie;
    char* err = "unknown error";

    D("wait_for_state %d\n", sinfo->state);

    atransport *t = acquire_one_transport(sinfo->state, sinfo->transport, sinfo->serial, &err);
    if(t != 0) {
        writex(fd, "OKAY", 4);
    } else {
        sendfailmsg(fd, err);
    }

    if (sinfo->serial)
        free(sinfo->serial);
    free(sinfo);
    sdb_close(fd);
    D("wait_for_state is done\n");
}
#endif

#if SDB_HOST
asocket*  host_service_to_socket(const char*  name, const char *serial)
{
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker();
    } else if (!strncmp(name, "wait-for-", strlen("wait-for-"))) {
        struct state_info* sinfo = malloc(sizeof(struct state_info));

        if (serial)
            sinfo->serial = strdup(serial);
        else
            sinfo->serial = NULL;

        name += strlen("wait-for-");

        if (!strncmp(name, "local", strlen("local"))) {
            sinfo->transport = kTransportLocal;
            sinfo->state = CS_DEVICE;
        } else if (!strncmp(name, "usb", strlen("usb"))) {
            sinfo->transport = kTransportUsb;
            sinfo->state = CS_DEVICE;
        } else if (!strncmp(name, "any", strlen("any"))) {
            sinfo->transport = kTransportAny;
            sinfo->state = CS_DEVICE;
        } else {
            free(sinfo);
            return NULL;
        }

        int fd = create_service_thread(wait_for_state, sinfo);
        return create_local_socket(fd);
    }
    return NULL;
}
#endif /* SDB_HOST */
