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

#define TRACE_TAG  TRACE_APPCMD

#include "sysdeps.h"
#include "sdb.h"
#include "sdktools.h"
#include "strutils.h"
#include "utils.h"

#if APPCMD_USING_PKGMGR
#include <pkgmgr-info.h>
#include <package-manager.h>
#endif

#include <tzplatform_config.h>

#define APPCMD_EXITCODE_PREFIX  "appcmd_exitcode"
#define APPCMD_RETURNSTR_PREFIX "appcmd_returnstr"
#define APPCMD_RESULT_BUFSIZE   (4096)

typedef struct appcmd_info appcmd_info;
typedef int (*appcmd_gen_shellcmd)(appcmd_info*);
typedef void (*appcmd_receiver)(int, int);
struct appcmd_info {
    int fd;

    char* args[MAX_TOKENS];
    size_t args_cnt;
    char* raw_command;

    appcmd_gen_shellcmd gen_cmd_func;
    appcmd_receiver receiver_func;

    char shell_cmd[SDBD_SHELL_CMD_MAX];

    int exitcode;
};

static int appcmd_install_gen_shellcmd(appcmd_info* p_info) {
    char *type = NULL;
    char *pkgpath = NULL;
    char *pkgid = NULL;
    char *teppath = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 5) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    type = p_info->args[1];
    pkgpath = p_info->args[2];
    pkgid = p_info->args[3];
    teppath = p_info->args[4];

    D("args: type=%s, pkgpath=%s, pkgid=%s, teppath=%s\n", type, pkgpath, pkgid, teppath);

    if (strncmp(pkgid, "null", 4) == 0) {
        if (strncmp(teppath, "null", 4) == 0) {
            /* Normal install case */
            snprintf(buf, len, "pkgcmd -i -q -t %s -p %s -G", type, pkgpath);
        } else {
            /* TEP install case */
            snprintf(buf, len, "pkgcmd -i -q -p %s -e %s -G", pkgpath, teppath);
        }
    } else {
        /* Re-install case */
        snprintf(buf, len, "pkgcmd -r -q -t %s -n %s", type, pkgid);
    }

    return 0;
}

static int appcmd_uninstall_gen_shellcmd(appcmd_info* p_info) {
    char *type = NULL;
    char *pkgid = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 3) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    type = p_info->args[1];
    pkgid = p_info->args[2];

    D("args: type=%s, pkgid=%s\n", type, pkgid);

    snprintf(buf, len, "pkgcmd -u -q -t %s -n %s", type, pkgid);

    return 0;
}

static int appcmd_runapp_gen_shellcmd(appcmd_info* p_info) {
    char *type = NULL;
    char *appid = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 3) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    type = p_info->args[1];
    appid = p_info->args[2];

    D("args: type=%s, appid=%s\n", type, appid);

    if (strncmp(type, "wgt", 3) == 0 || strncmp(type, "tpk", 3) == 0) {
        snprintf(buf, len, "/usr/bin/app_launcher --start %s", appid);
    } else {
        D("not supported package type. (%s)\n", type);
        return -1;
    }

    return 0;
}

static int appcmd_rununittestapp_gen_shellcmd(appcmd_info* p_info) {
    char *appid = NULL;
    char *usr_args = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);
    char *ptr = NULL;
    char *p_service = NULL;
    char *p_appid = NULL;

    free_strings(p_info->args, p_info->args_cnt);

    p_service = strtok_r(p_info->raw_command, ":", &ptr);
    p_appid = strtok_r(NULL, ":", &ptr);
    if (p_service == NULL || p_appid == NULL) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    p_info->args_cnt = 3;
    p_info->args[0] = strdup(p_service);
    p_info->args[1] = strdup(p_appid);
    p_info->args[2] = strdup(ptr);

    appid = p_info->args[1];
    usr_args = p_info->args[2];

    D("args: appid=%s, usr_args=%s\n", appid, usr_args);

    snprintf(buf, len, "/usr/bin/app_launcher -s %s __AUL_SDK__ UNIT_TEST __LAUNCH_APP_MODE__ SYNC __DLP_UNIT_TEST_ARG__ \'%s\'", appid, usr_args);

    return 0;
}

static int appcmd_killapp_gen_shellcmd(appcmd_info* p_info) {
    char *type = NULL;
    char *appid = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 3) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    type = p_info->args[1];
    appid = p_info->args[2];

    D("args: type=%s, appid=%s\n", type, appid);

    if (strncmp(type, "wgt", 3) == 0) {
        /* Web application */
        char* q = strchr(appid, '.');
        if (q != NULL)
            *q++ = '\0';
    }

    snprintf(buf, len, "pkgcmd -k -t %s -n %s", type, appid);

    return 0;
}

static int appcmd_packagelist_gen_shellcmd(appcmd_info* p_info) {
    char *type = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 2) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    type = p_info->args[1];

    D("args: type=%s\n", type);

    snprintf(buf, len, "/usr/bin/pkgcmd -l -t %s", type);

    return 0;
}

static int appcmd_debugwebapp_gen_shellcmd(appcmd_info* p_info) {
    char *appid = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 2) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    appid = p_info->args[1];

    D("args: appid=%s\n", appid);

    snprintf(buf, len, "/usr/bin/app_launcher --start %s -w", appid);

    return 0;
}

static int appcmd_debugnativeapp_gen_shellcmd(appcmd_info* p_info) {
    char *debug_port = NULL;
    char *appid= NULL;
    char *pid_str = NULL;
    char *gdbserver_path = NULL;
    char *buf = p_info->shell_cmd;
    int pid = -1;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 5) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    debug_port = p_info->args[1];
    appid= p_info->args[2];
    pid_str = p_info->args[3];
    gdbserver_path = p_info->args[4]; // not used. for 3.0 platform.

    pid = atoi(pid_str);
    D("args: debug_port=%s, appid=%s, pid=%d, gdbserver_path=%s\n", debug_port, appid, pid, gdbserver_path);

    if (pid == -1) {
        snprintf(buf, len, "/usr/bin/app_launcher --start %s __AUL_SDK__ DEBUG __DLP_DEBUG_ARG__ :%s __DLP_GDBSERVER_PATH__ %s", appid, debug_port, gdbserver_path);
    } else {
        /* attach mode */
        snprintf(buf, len, "/usr/bin/launch_debug %s __AUL_SDK__ ATTACH __DLP_GDBSERVER_PATH__ %s __DLP_ATTACH_ARG__ --attach,:%s,%d", appid, gdbserver_path, debug_port, pid);
    }

    return 0;
}

static void appcmd_receiver_debugwebapp(int fd_in, int fd_out)
{
    char buf[4096] = {0,};
    char port_str[32] = {0,};
    char out_buf[128] = {0,};
    char* sub_str = NULL;
    int r;

    for(;;) {
        memset(buf, 0, sizeof(buf));
        r = read_line(fd_in, buf, sizeof(buf));
        if (r == 0) {
            break;
        } else if(r < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                break;
            }
        }

        D("debug webapp output : %s\n", buf);
        sub_str = strstr(buf, "port: ");
        if (sub_str != NULL && sscanf(sub_str, "port: %s", port_str) == 1) {
            snprintf(out_buf, sizeof(out_buf), "\n%s:%s\n", APPCMD_RETURNSTR_PREFIX, port_str);
            writex(fd_out, out_buf, strlen(out_buf)+1);
            break;
        }
    }
}

static void appcmd_receiver_default(int fd_in, int fd_out)
{
    char buf[4096] = {0,};
    int r;

    for(;;) {
        memset(buf, 0, sizeof(buf));
        r = sdb_read(fd_in, buf, sizeof(buf));
        if (r == 0) {
            break;
        } else if(r < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                break;
            }
        }

        writex(fd_out, buf, strlen(buf)+1);
    }
}

static void appcmd_receiver_packagelist(int fd_in, int fd_out)
{
    char buf[4096] = {0,};
    char out_buf[4096] = {0,};
    int out_ptr = 0;
    int r;

    snprintf(out_buf, sizeof(out_buf), "\n%s", APPCMD_RETURNSTR_PREFIX);
    out_ptr = strlen(out_buf);

    for(;;) {
        memset(buf, 0, sizeof(buf));
        r = read_line(fd_in, buf, sizeof(buf));
        if (r == 0) {
            break;
        } else if(r < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                break;
            }
        }

        D("pkgcmd output : %s\n", buf);
        char* sub1 = NULL;
        char* sub2 = NULL;
        sub1 = strstr(buf, "pkgid [");
        if (sub1 != NULL) {
            sub1 = strstr(sub1, "[")+1;
            sub2 = strstr(sub1, "]");
            sub2[0] = '\0';

            snprintf(out_buf+out_ptr, sizeof(out_buf)-out_ptr, ":%s", sub1);
            out_ptr += strlen(sub1)+1;
        }
    }

    snprintf(out_buf+out_ptr, sizeof(out_buf)-out_ptr, "\n");

    D("package list: %s\n", out_buf);
    writex(fd_out, out_buf, strlen(out_buf)+1);
}

static int exec_appcmd_shell_process(appcmd_info* p_info) {
    int ptm_fd = -1;
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

    // For the SDK user privilege.
    envp[2] = "HOME=/home/developer";
    get_env("ENV_PATH", &value);
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

    char *args[] = {
        SHELL_COMMAND,
        "-c",
        NULL,
        NULL,
    };
    args[2] = p_info->shell_cmd;

    ptm_fd = create_subprocess(SHELL_COMMAND, &pid, (char * const*)args, (char * const*)envp);
    D("create_subprocess() ptm_fd=%d pid=%d\n", ptm_fd, pid);
    if (ptm_fd < 0) {
        D("cannot create service thread\n");
        return -1;
    }

    if (p_info->receiver_func != NULL) {
        p_info->receiver_func(ptm_fd, p_info->fd);
    }

    // wait for shell process
    for (;;) {
        int status;
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            D("fd=%d, post waitpid(pid=%d) status=%04x\n", p_info->fd, p, status);

            if (WIFEXITED(status)) {
                p_info->exitcode = WEXITSTATUS(status);
                D("*** Exit code %d\n", p_info->exitcode);
                break;
            }
        }
    }
    D("shell exited fd=%d of pid=%d err=%d\n", p_info->fd, pid, errno);

    return 0;
}

#if APPCMD_USING_PKGMGR
static int get_pkg_info(char* pkgid, char* pkginfo_buf, int buf_size) {
    pkgmgrinfo_pkginfo_h handle;
    pkgmgr_client* pc = NULL;
    char* pkgname = NULL;
    char* type = NULL;
    bool is_removable = 0;
    int is_running = 0;
    int ret = -1;
    int pid = -1;

    ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
    if (ret < 0) {
        D("failed to get pkginfo handle.\n");
        return -1;
    }

    ret = pkgmgrinfo_pkginfo_get_mainappid(handle, &pkgname);
    if (ret < 0) {
        D("failed to get pkg name\n");
        return -1;
    }

    ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
    if (ret < 0) {
        D("failed to get pkg type.\n");
        return -1;
    }

    ret = pkgmgrinfo_pkginfo_is_removable(handle, &is_removable);
    if (ret < 0) {
        D("failed to get removable info.\n");
        return -1;
    }

    pc = pkgmgr_client_new(PC_REQUEST);
    if (pc == NULL) {
        D("failed to create pkgmgr client.\n");
        return -1;
    }

    ret = pkgmgr_client_request_service(PM_REQUEST_CHECK_APP, 0, pc, NULL, pkgid, NULL, NULL, &pid);
    if (ret < 0) {
        D("failed to get running state.\n");
        return -1;
    }
    is_running = ((pid > 0) ? 1:0);

    D("pkginfo: pkgname=%s, type=%s, is_removagle=%d, is_running=%d, pid=%d\n", pkgname, type, is_removable, is_running, pid);
    snprintf(pkginfo_buf, buf_size, "%s:%s:%d:%d", pkgname, type, is_removable, is_running);
    return 0;
}

static void run_appcmd_packageinfo(appcmd_info* p_info) {
    char result_buf[APPCMD_RESULT_BUFSIZE] = {0,};
    char pkginfo_buf[256] = {0,};
    char *type = NULL;
    char *pkgid = NULL;

    p_info->exitcode = -1;

    if (p_info->args_cnt != 3) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return;
    }

    type = p_info->args[1];
    pkgid= p_info->args[2];

    D("args: type=%s, pkgid=%s\n", type, pkgid);

    if (get_pkg_info(pkgid, pkginfo_buf, sizeof(pkginfo_buf)) == 0) {
        D("success to get pkginfo. (%s)\n", pkginfo_buf);
        p_info->exitcode = 0;
        snprintf(result_buf, sizeof(result_buf), "\n%s:%s\n", APPCMD_RETURNSTR_PREFIX, pkginfo_buf);
        writex(p_info->fd, result_buf, strlen(result_buf));
    } else {
        D("failed to get pkginfo.\n");
    }
}
#else
static int appcmd_packageinfo_gen_shellcmd(appcmd_info* p_info) {
    char *pkgid = NULL;
    char *buf = p_info->shell_cmd;
    int len = sizeof(p_info->shell_cmd);

    if (p_info->args_cnt != 2) {
        D("failed to parse appcmd.(cnt=%d)\n", p_info->args_cnt);
        return -1;
    }

    pkgid = p_info->args[1];

    D("args: pkgid=%s\n", pkgid);

    snprintf(buf, len, "/usr/bin/pkginfo --pkg %s;/usr/bin/pkgcmd -C -n %s", pkgid, pkgid);

    return 0;
}

static void appcmd_receiver_packageinfo(int fd_in, int fd_out)
{
    char buf[4096] = {0,};
    char pkgname[128] = {0,};
    char type[128] = {0,};
    int is_removable = 0;
    int is_running = 0;
    int r;

    for(;;) {
        memset(buf, 0, sizeof(buf));
        r = read_line(fd_in, buf, sizeof(buf));
        if (r == 0) {
            break;
        } else if(r < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                break;
            }
        }

        if (!strncmp(buf, "mainappid : ", 12)) {
            sscanf(buf, "mainappid : %s", pkgname);
        } else if (!strncmp(buf, "Type: ", 6)) {
            sscanf(buf, "Type: %s", type);
        } else if (!strncmp(buf, "Removable: ", 11)) {
            sscanf(buf, "Removable: %d", &is_removable);
        } else if (strstr(buf, " is Running") != NULL) {
            is_running = 1;
        }
    }

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "\n%s:%s:%s:%d:%d\n",
                APPCMD_RETURNSTR_PREFIX, pkgname, type, is_removable, is_running);

    D("package info: %s\n", buf);
    writex(fd_out, buf, strlen(buf)+1);
}
#endif

static void run_appcmd_appinstallpath(appcmd_info* p_info) {
    char result_buf[APPCMD_RESULT_BUFSIZE] = {0,};

    p_info->exitcode = -1;

    const char* path = tzplatform_getenv(TZ_SDK_HOME);
    if (path != NULL) {
        p_info->exitcode = 0;
        snprintf(result_buf, sizeof(result_buf), "\n%s:%s/apps_rw/\n", APPCMD_RETURNSTR_PREFIX, path);
        writex(p_info->fd, result_buf, strlen(result_buf));
    } else {
        D("failed to get application install path from tzplatform_getenv.");
    }
}

static void run_appcmd_with_shell_process(appcmd_info* p_info) {
    int ret = -1;

    if (p_info == NULL || p_info->gen_cmd_func == NULL) {
        D("Invalid arguments.\n");
        p_info->exitcode = -1;
        return;
    }

    ret = p_info->gen_cmd_func(p_info);
    if (ret < 0) {
        D("failed to generate install shell command.\n");
        p_info->exitcode = -1;
    } else {
        ret = exec_appcmd_shell_process(p_info);
        D("exec_appcmd_shell_process: ret=%d, exitcode=%d\n", ret, p_info->exitcode);
        if (ret < 0) {
            D("failed to run shell process\n");
            p_info->exitcode = -1;
        }
    }
}

void appcmd_service(int fd, char* command) {
    appcmd_info info;
    char result_buf[APPCMD_RESULT_BUFSIZE] = {0,};
    char* service_name = NULL;

    D("command=%s(FD:%d)\n", command, fd);

    memset(&info, 0, sizeof(info));

    /* appcmd parameter data map
     * "service name:arg1:arg2:...:argN" */
    info.args_cnt = tokenize(command, ":", info.args, MAX_TOKENS);
    D("args_cnt=%d\n", info.args_cnt);
    if (info.args_cnt < 1) {
        D("failed to parse appcmd for install. (%s)\n", command);
        info.exitcode = -1;
        goto appcmd_done;
    }

    info.fd = fd;
    info.exitcode = -1;
    info.raw_command = command;

    service_name = info.args[0];
    D("service name=%s\n", service_name);

    if (strncmp(service_name, "install", 7) == 0) {
        info.receiver_func = appcmd_receiver_default;
        info.gen_cmd_func = appcmd_install_gen_shellcmd;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "uninstall", 9) == 0) {
        info.receiver_func = appcmd_receiver_default;
        info.gen_cmd_func = appcmd_uninstall_gen_shellcmd;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "packageinfo", 11) == 0) {
#if APPCMD_USING_PKGMGR
        run_appcmd_packageinfo(&info);
#else
        info.gen_cmd_func = appcmd_packageinfo_gen_shellcmd;
        info.receiver_func = appcmd_receiver_packageinfo;
        run_appcmd_with_shell_process(&info);
#endif
    } else if (strncmp(service_name, "packagelist", 11) == 0) {
        info.gen_cmd_func = appcmd_packagelist_gen_shellcmd;
        info.receiver_func = appcmd_receiver_packagelist;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "appinstallpath", 14) == 0) {
        run_appcmd_appinstallpath(&info);
    } else if (strncmp(service_name, "runapp", 6) == 0) {
        info.receiver_func = appcmd_receiver_default;
        info.gen_cmd_func = appcmd_runapp_gen_shellcmd;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "rununittestapp", 14) == 0) {
        info.receiver_func = appcmd_receiver_default;
        info.gen_cmd_func = appcmd_rununittestapp_gen_shellcmd;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "killapp", 7) == 0) {
        info.receiver_func = appcmd_receiver_default;
        info.gen_cmd_func = appcmd_killapp_gen_shellcmd;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "debugwebapp", 11) == 0) {
        info.gen_cmd_func = appcmd_debugwebapp_gen_shellcmd;
        info.receiver_func = appcmd_receiver_debugwebapp;
        run_appcmd_with_shell_process(&info);
    } else if (strncmp(service_name, "debugnativeapp", 14) == 0) {
        info.gen_cmd_func = appcmd_debugnativeapp_gen_shellcmd;
        run_appcmd_with_shell_process(&info);
    } else {
        D("not supported appcmd service. (%s)\n", service_name);
        info.exitcode = -1;
        goto appcmd_done;
    }

appcmd_done:
    free_strings(info.args, info.args_cnt);

    snprintf(result_buf, sizeof(result_buf), "\n%s:%d\n", APPCMD_EXITCODE_PREFIX, info.exitcode);
    writex(fd, result_buf, strlen(result_buf));
}
