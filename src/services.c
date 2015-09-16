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
#include <system_info.h>
#include <vconf.h>
#include <limits.h>

#include <termios.h>
#include <sys/ioctl.h>

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

static int is_support_interactive_shell()
{
    return (!strncmp(g_capabilities.intershell_support, SDBD_CAP_RET_ENABLED, strlen(SDBD_CAP_RET_ENABLED)));
}

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

static int is_support_rootonoff()
{
    return (!strncmp(g_capabilities.rootonoff_support, SDBD_CAP_RET_ENABLED, strlen(SDBD_CAP_RET_ENABLED)));
}

void rootshell_service(int fd, void *cookie)
{
    char buf[100];
    char *mode = (char*) cookie;

    if (!strcmp(mode, "on")) {
        if (getuid() == 0) {
            if (rootshell_mode == 1) {
                //snprintf(buf, sizeof(buf), "Already changed to developer mode\n");
                // do not show message
            } else {
                if (is_support_rootonoff()) {
                    rootshell_mode = 1;
                    //allows a permitted user to execute a command as the superuser
                    snprintf(buf, sizeof(buf), "Switched to 'root' account mode\n");
                } else {
                    snprintf(buf, sizeof(buf), "Permission denied\n");
                }
                writex(fd, buf, strlen(buf));
            }
        } else {
            D("need root permission for root shell: %d\n", getuid());
            rootshell_mode = 0;
            snprintf(buf, sizeof(buf), "Permission denied\n");
            writex(fd, buf, strlen(buf));
        }
    } else if (!strcmp(mode, "off")) {
        if (rootshell_mode == 1) {
            rootshell_mode = 0;
            snprintf(buf, sizeof(buf), "Switched to 'developer' account mode\n");
            writex(fd, buf, strlen(buf));
        }
    } else if ((!strcmp(mode, "hoston")) && (is_container_enabled())) {
        if (hostshell_mode == 1) {
    	//snprintf(buf, sizeof(buf), "Already changed to hostshell mode\n");
    	// do not show message
    	} else {
            if (is_support_rootonoff()) {
    	        hostshell_mode = 1;
    	        snprintf(buf, sizeof(buf), "Switched to host shell mode\n");
    	    } else {
    	        snprintf(buf, sizeof(buf), "Permission denied\n");
    	    }
    	    writex(fd, buf, strlen(buf));
    	}
    } else if ((!strcmp(mode, "hostoff")) && (is_container_enabled())) {
        if (hostshell_mode == 1) {
            if(has_container()) {
                hostshell_mode = 0;
                snprintf(buf, sizeof(buf), "Switched to foreground zone shell mode\n");
                writex(fd, buf, strlen(buf));
            } else {
                snprintf(buf, sizeof(buf), "No foreground zone exists\n");
                writex(fd, buf, strlen(buf));
            }
        }
    } else {
    	snprintf(buf, sizeof(buf), "Unknown command option : %s\n", mode);
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
        snprintf(buf, sizeof(buf), "reboot failed: %s errno:%d\n", errno);
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
        while (i >= 0 && i <= (length - EVENT_SIZE)) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            if (event->len) {
                if (event->mask & IN_CREATE) {
                    if (!(event->mask & IN_ISDIR)) {
                        char *cspath = NULL;
                        int len = asprintf(&cspath, "%s/%s", CS_PATH,
                                event->name);
                        D( "The file %s was created.\n", cspath);
                        writex(fd, cspath, len);
                        if (cspath != NULL) {
                            free(cspath);
                        }
                    }
                }
            }
            if (i + EVENT_SIZE + event->len < event->len) { // in case of integer overflow
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

static void redirect_and_exec(int pts, const char *cmd, const char *argv[], const char *envp[])
{
    dup2(pts, 0);
    dup2(pts, 1);
    dup2(pts, 2);

    sdb_close(pts);

    execve(cmd, argv, envp);
}

static int create_subprocess(const char *cmd, pid_t *pid, const char *argv[], const char *envp[])
{
    char devname[64];
    int ptm;

    ptm = unix_open("/dev/ptmx", O_RDWR); // | O_NOCTTY);
    if(ptm < 0){
        D("[ cannot open /dev/ptmx - errno:%d ]\n",errno);
        return -1;
    }
    if (fcntl(ptm, F_SETFD, FD_CLOEXEC) < 0) {
        D("[ cannot set cloexec to /dev/ptmx - errno:%d ]\n",errno);
    }

    if(grantpt(ptm) || unlockpt(ptm) ||
        ptsname_r(ptm, devname, sizeof(devname)) != 0 ){
        D("[ trouble with /dev/ptmx - errno:%d ]\n", errno);
        sdb_close(ptm);
        return -1;
    }

    *pid = fork();
    if(*pid < 0) {
        D("- fork failed: errno:%d -\n", errno);
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
               D("sdb: unable to open %s due to errno:%d\n", text, errno);
            }
        }

        if (hostshell_mode == 1) {
            if (should_drop_privileges()) {
                if (argv[2] != NULL && getuid() == 0 && request_plugin_verification(SDBD_CMD_VERIFY_ROOTCMD, argv[2])) {
                    // do nothing
                    D("sdb: executes root commands!!:%s\n", argv[2]);
                } else {
                    set_developer_privileges();
                }
            }
		        redirect_and_exec(pts, cmd, argv, envp);
		} else {
			char **pargv, **pargv_attach, sid[16];
			char *argv_attach[16] = {
			   CMD_ATTACH,
			   "-f",
			   NULL,
			};
			pargv_attach = argv_attach + 2;

			if (should_drop_privileges()) {
				if (argv[2] != NULL && request_plugin_verification(SDBD_CMD_VERIFY_ROOTCMD, argv[2])) {
					// do nothing
					D("sdb: executes root commands!!:%s\n", argv[2]);
				} else {
					snprintf(sid, 16, "%d", SID_DEVELOPER);
					*(pargv_attach++) = "--uid";
					*(pargv_attach++) = sid;
					*(pargv_attach++) = "--gid";
					*(pargv_attach++) = sid;

					if (chdir("/home/developer") < 0) {
						D("sdbd: unable to change working directory to /home/developer\n");
					} else {
						if (chdir("/") < 0) {
							D("sdbd: unable to change working directory to /\n");
						}
					}
					// TODO: use pam later
					//putenv("HOME=/home/developer");
					setenv("HOME", "/home/developer", 1);
				}
			}
			*(pargv_attach++) = "--";
			pargv = argv;
			while(*pargv) {
				*(pargv_attach++) = *(pargv++);
			}
			redirect_and_exec(pts, CMD_ATTACH, argv_attach, envp);
		}
		fprintf(stderr, "- exec '%s' failed: (errno:%d) -\n",
			cmd, errno);
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

static int create_subproc_thread(const char *name, int lines, int columns)
{
    stinfo *sti;
    sdb_thread_t t;
    int ret_fd;
    pid_t pid;
    char *value = NULL;
    char *trim_value = NULL;
    char path[PATH_MAX];
    memset(path, 0, sizeof(path));

    char *envp[] = {
        "TERM=linux", /* without this, some programs based on screen can't work, e.g. top */
        "DISPLAY=:0", /* without this, some programs based on without launchpad can't work */
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    };

    if (should_drop_privileges()) {
         envp[2] = "HOME=/home/developer";
         get_env("ENV_PATH", &value);
     } else {
         get_env("ENV_SUPATH", &value);
         if(value == NULL) {
             get_env("ENV_ROOTPATH", &value);
         }
         envp[2] = "HOME=/root";
     }
    if (value != NULL) {
        trim_value = str_trim(value);
        if (trim_value != NULL) {
            // if string is not including 'PATH=', append it.
            if (strncmp(trim_value, "PATH", 4)) {
                snprintf(path, sizeof(path), "PATH=%s", trim_value);
            } else {
                snprintf(path, sizeof(path), "%s", trim_value);
            }
            envp[3] = path;
            free(trim_value);
        } else {
            envp[3] = value;
        }
    }

    D("path env:%s,%s,%s,%s\n", envp[0], envp[1], envp[2], envp[3]);

    if(name) { // in case of shell execution directly
        // Check the shell command validation.
        if (!request_plugin_verification(SDBD_CMD_VERIFY_SHELLCMD, name)) {
            D("This shell command is invalid. (%s)\n", name);
            return -1;
        }

        // Convert the shell command.
        char *new_cmd = NULL;
        new_cmd = malloc(SDBD_SHELL_CMD_MAX);
        if(new_cmd == NULL) {
            D("Cannot allocate the shell commnad buffer.");
            return -1;
        }

        memset(new_cmd, 0, SDBD_SHELL_CMD_MAX);
        if(!request_plugin_cmd(SDBD_CMD_CONV_SHELLCMD, name, new_cmd, SDBD_SHELL_CMD_MAX)) {
            D("Failed to convert the shell command. (%s)\n", name);
            free(new_cmd);
            return -1;
        }

        D("converted cmd : %s\n", new_cmd);

        char *args[] = {
            SHELL_COMMAND,
            "-c",
            NULL,
            NULL,
        };
        args[2] = new_cmd;

        ret_fd = create_subprocess(SHELL_COMMAND, &pid, args, envp);
        free(new_cmd);
    } else { // in case of shell interactively
        // Check the capability for interactive shell support.
        if (!is_support_interactive_shell()) {
            D("This platform dose NOT support the interactive shell\n");
            return -1;
        }

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

    if (lines > 0 && columns > 0) {
        D("shell size lines=%d, columns=%d\n", lines, columns);
        struct winsize win_sz;
        win_sz.ws_row = lines;
        win_sz.ws_col = columns;

        if (ioctl(ret_fd, TIOCSWINSZ, &win_sz) < 0) {
            D("failed to sync window size.\n");
        }
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
        D("- fork failed: errno:%d -\n", errno);
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

static void get_platforminfo(int fd, void *cookie) {
    pinfo sysinfo;

    char *value = NULL;
    s_strncpy(sysinfo.platform_info_version, INFO_VERSION, strlen(INFO_VERSION));

    int r = system_info_get_platform_string("http://tizen.org/system/model_name", &value);
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

    r = system_info_get_platform_string("http://tizen.org/system/platform.name", &value);
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

static int put_key_value_string(char* buf, int offset, int buf_size, char* key, char* value) {
    int len = 0;
    if ((len = snprintf(buf+offset, buf_size-offset, "%s:%s\n", key, value)) > 0) {
        return len;
    }
    return 0;
}

static void get_capability(int fd, void *cookie) {
    char cap_buffer[CAPBUF_SIZE] = {0,};
    uint16_t offset = 0;

    // Secure protocol support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "secure_protocol", g_capabilities.secure_protocol);

    // Interactive shell support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "intershell_support", g_capabilities.intershell_support);

    // File push/pull support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "filesync_support", g_capabilities.filesync_support);

    // USB protocol support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "usbproto_support", g_capabilities.usbproto_support);

    // Socket protocol support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "sockproto_support", g_capabilities.sockproto_support);

    // Root command support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "rootonoff_support", g_capabilities.rootonoff_support);

    // Zone support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "zone_support", g_capabilities.zone_support);

    // Multi-User support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "multiuser_support", g_capabilities.multiuser_support);

    // CPU Architecture of model
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "cpu_arch", g_capabilities.cpu_arch);

    // Profile name
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "profile_name", g_capabilities.profile_name);

    // Vendor name
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "vendor_name", g_capabilities.vendor_name);

    // Platform version
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "platform_version", g_capabilities.platform_version);

    // Product version
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "product_version", g_capabilities.product_version);

    // Sdbd version
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "sdbd_version", g_capabilities.sdbd_version);

    // Sdbd plugin version
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "sdbd_plugin_version", g_capabilities.sdbd_plugin_version);

    // Window size synchronization support
    offset += put_key_value_string(cap_buffer, offset, CAPBUF_SIZE,
                                "syncwinsz_support", g_capabilities.syncwinsz_support);


    offset++; // for '\0' character

    writex(fd, &offset, sizeof(uint16_t));
    writex(fd, cap_buffer, offset);

    sdb_close(fd);
}

static void sync_windowsize(int fd, void *cookie) {
    int id, lines, columns;
    char *size_info = cookie;
    asocket *s = NULL;

    if (sscanf(size_info, "%d:%d:%d", &id, &lines, &columns) == 3) {
        D("window size information: id=%d, lines=%d, columns=%d\n", id, lines, columns);
    }
    if((s = find_local_socket(id))) {
        struct winsize win_sz;
        win_sz.ws_row = lines;
        win_sz.ws_col = columns;

        if (ioctl(s->fd, TIOCSWINSZ, &win_sz) < 0) {
            D("failed to sync window size.\n");
            return;
        }
        D("success to sync window size.\n");
    }
}

const unsigned COMMAND_TIMEOUT = 10000;
void get_boot(int fd, void *cookie) {
    char buf[2] = { 0, };
    char *mode = (char*) cookie;
    int time = 0;
    int interval = 1000;
    while (time < COMMAND_TIMEOUT) {
        if (booting_done == 1) {
            D("get_boot:platform booting is done\n");
            snprintf(buf, sizeof(buf), "%s", "1");
            break;
        }
        D("get_boot:platform booting is in progress\n");
        sdb_sleep_ms(interval);
        time += interval;
    }
    writex(fd, buf, strlen(buf));
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
            ret = create_subproc_thread(name + 6, 0, 0);
        } else {
            ret = create_subproc_thread(NULL, 0, 0);
        }
    } else if(!strncmp(name, "eshell:", 7)) {
        int lines, columns;
        if (sscanf(name+7, "%d:%d", &lines, &columns) == 2) {
            ret = create_subproc_thread(NULL, lines, columns);
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
    } else if(!strncmp(name, "capability:", 11)){
        ret = create_service_thread(get_capability, 0);
    } else if(!strncmp(name, "boot:", 5)){
        if (is_emulator()) {
            ret = create_service_thread(get_boot, 0);
        }
    } else if(!strncmp(name, "shellconf:", 10)){
        if(!strncmp(name+10, "syncwinsz:", 10)){
            ret = create_service_thread(sync_windowsize, name+20);
        }
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
