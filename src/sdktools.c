#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <regex.h>

#include "sysdeps.h"
#include "smack.h"
#include "sdktools.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "sdb.h"
#include "sdktools.h"
#include "strutils.h"

struct sudo_command root_commands[] = {
    /* 0 */ {"gdbserver", "/home/developer/sdk_tools/gdbserver/gdbserver"},
    /* 1 */ {"killall", "/usr/bin/killall"},
    /* 3 */ {"pkgcmd", "/usr/bin/pkgcmd"},
    /* 4 */ {"launch_app", "/usr/bin/launch_app"},
    /* 5 */ {"dlogutil", "/usr/bin/dlogutil"},
    /* 6 */ {"LD_PRELOAD", "LD_PRELOAD=/usr/lib/da_probe_osp.so"},
    /* end */ {NULL, NULL}
};

int verify_commands(const char *arg1) {
    if (arg1 != NULL) {
        if (verify_root_commands(arg1)) {
            // do not drop privilege only if root auth is required
            return 1;
        }
    }
    // doing these steps if we don't have root permission
    if (should_drop_privileges()) {
        set_developer_privileges();
    }
    return 1;
}

/**
 * Returns 1 if the command is root, otherwise 0.
 */
int verify_root_commands(const char *arg1) {
    char *tokens[MAX_TOKENS];
    size_t cnt;
    int ret = 0;
    int i=0;
    int index = -1;

    cnt = tokenize(arg1, " ", tokens, MAX_TOKENS);
    for (i=0; i<cnt; i++) {
        D("tokenize: %dth: %s\n", i, tokens[i]);
    }
    if (cnt == 0 ) {
        return 0; // just keep going to execute normal commands
    }
    index = is_root_commands(tokens[0]);
    if (index == -1) {
        return 0; // just keep going to execute normal commands
    }

    D("cmd processing......: %s\n", arg1);
    switch (index) {
    case 0: {
        if (cnt == 3) { // gdbserver :1234 /opt/apps/appid/bin/executable.exe
            char *new_appid = clone_gdbserver_label_from_app(tokens[2]);
            if (new_appid != NULL) {
                if (smack_set_label_for_self(new_appid) != -1) {
                    D("set smack lebel [%s] appid to %s\n", new_appid, SMACK_LEBEL_SUBJECT_PATH);
                    apply_app_process();
                    ret = 1;
                } else {
                    D("unable to open %s due to %s\n", SMACK_LEBEL_SUBJECT_PATH, strerror(errno));
                }
                free(new_appid);
            }
        }
        if (cnt == 4) { // gdbserver :1234 --attach pid
            int pid = 0;
            char cmdline[128];
            pid = atoi(tokens[3]);
            if (pid) {
                snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);
                int fd = unix_open(cmdline, O_RDONLY);
                if (fd) {
                    if(read_line(fd, cmdline, sizeof(cmdline))) {
                        if (verify_app_path(cmdline)) {
                            apply_app_process();
                            ret = 1;
                        }
                    }
                    sdb_close(fd);
                }
            }
        }
        break;
    }
    case 1: {
        if (cnt == 2) {
            if (verify_app_path(tokens[1])) {
                ret = 1;
            }
        }
        break;
    }
    case 2: {
        ret = 1;
        break;
    }
    case 3: {
        ret = 1;
        break;
    }
    case 4: {
        ret = 1;
        break;
    }
    case 5: {
        if (cnt == 2) {
            if (verify_app_path(tokens[1])) {
                apply_app_process();
                ret = 1;
            }
        }
        break;
    }
    default: {
        break;
    }
    }
    D("doing the cmd as a %s\n", ret == 1 ? "root" : "developer");

    if (cnt) {
        free_strings(tokens, cnt);
    }

    return ret;
}

int verify_app_path(const char* path) {
    regex_t regex;
    int ret;
    char buf[PATH_MAX];

    snprintf(buf, sizeof buf, "^((%s)|(%s))/[a-zA-Z0-9]{%d}/bin/[a-zA-Z0-9_\\-]{1,}(\\.exe)?$", APP_INSTALL_PATH_PREFIX1, APP_INSTALL_PATH_PREFIX2, APPID_MAX_LENGTH);

    ret = regcomp(&regex, buf, REG_EXTENDED);
    if( ret ){ // not match
        return 0;
    }

    // execute regular expression
    ret = regexec(&regex, path, 0, NULL, 0);
    if(!ret){
        return 1;
    } else if( ret == REG_NOMATCH ){
        D("Not valid application path\n");
    } else{
        regerror(ret, &regex, buf, sizeof(buf));
        D("Regex match failed: %s\n", buf);
    }
    return 0;
}
int get_appid(const char* path, char* appid) {
    char *tokens[MAX_TOKENS];
    int ret = 0;

    if (verify_app_path(path)) {
        return 0;
    }

    size_t arg_cnt = tokenize(path, "/",tokens, MAX_TOKENS);

    if (arg_cnt == 5 && strlen(tokens[2]) == APPID_MAX_LENGTH) {
        strncpy(appid, tokens[2], APPID_MAX_LENGTH);
        ret = 1;
    }
    if (arg_cnt) {
        free_strings(tokens, arg_cnt);
    }
    return ret;
}

char* clone_gdbserver_label_from_app(const char* app_path) {
    char *new_appid = NULL;
    char appid[APPID_MAX_LENGTH];
    char *buffer = NULL;

    if (!verify_app_path(app_path)) {
        return NULL;
    }

    int rc = smack_lgetlabel(app_path, &buffer, SMACK_LABEL_EXEC);

    if (rc == 0 && buffer != NULL && strlen(buffer) == APPID_MAX_LENGTH) {
        strcpy(appid, buffer);
        free(buffer);
    } else {
        strcpy(appid, "_");
    }
    new_appid = (char *)malloc(sizeof(appid)+1);
    strncpy(new_appid, appid, APPID_MAX_LENGTH);
    if (new_appid != NULL) {
        rc = smack_lsetlabel(GDBSERVER_PATH, new_appid, SMACK_LABEL_ACCESS);
        if (rc < 0) {
            D("unable to set access smack label: %s to %s\n", GDBSERVER_PATH, new_appid);
        }
        D("set access smack label: %s to %s\n", GDBSERVER_PATH, new_appid);

        rc = smack_lsetlabel(GDBSERVER_PATH, new_appid, SMACK_LABEL_EXEC);
        if (rc < 0) {
            D("unable to set execute smack label: %s to %s\n", GDBSERVER_PATH, new_appid);
        }
        D("set execute smack label: %s to %s\n", GDBSERVER_PATH, new_appid);
    }

    return new_appid;
}

void apply_app_process() {
    set_appuser_groups();

    if (setgid(SID_APP) != 0) {
        fprintf(stderr, "set group id failed errno: %d\n", errno);
        exit(1);
    }

    if (setuid(SID_APP) != 0) {
        fprintf(stderr, "set user id failed errno: %d\n", errno);
        exit(1);
    }
}

void set_appuser_groups(void) {

    int fd = 0;
    char buffer[5];
    gid_t t_gid = -1;
    gid_t groups[APP_GROUPS_MAX];
    int cnt = 0;

    //groups[cnt++] = SID_DEVELOPER;
    fd = sdb_open(APP_GROUP_LIST, O_RDONLY);
    if (fd < 0) {
        D("cannot get app's group lists from %s", APP_GROUP_LIST);
        return;
    }
    for (;;) {
        if (read_line(fd, buffer, sizeof buffer) < 0) {
            break;
        }
        t_gid = strtoul(buffer, 0, 10);
        errno = 0;
        if(errno != 0)
        {
            D("cannot change string to integer: [%s]\n", buffer);
            continue;
        }
        if (t_gid) {
            if (cnt < APP_GROUPS_MAX) {
                groups[cnt++] = t_gid;
            } else {
                D("cannot add groups more than %d", APP_GROUPS_MAX);
                break;
            }
        }
    }
    if (cnt > 0) {
        if (setgroups(sizeof(groups) / sizeof(groups[0]), groups) != 0) {
           fprintf(stderr, "set groups failed errno: %d\n", errno);
           exit(1);
        }
    }
}

int is_root_commands(const char *command) {
    int i = -1;
    for(i = 0; root_commands[i].path != NULL; i++) {
        if(!strncmp(root_commands[i].path, command, PATH_MAX)) {
            return i;
        }
    }
    // not found
    return -1;
}
