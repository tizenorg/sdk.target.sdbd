#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysdeps.h"
#include "smack.h"
#include "sdktools.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "sdb.h"
#include "sdktools.h"
#include "strutils.h"
#include "fileutils.h"

struct sudo_command root_commands[] = {
    /* 0 */ {"killall", "/usr/bin/killall"},
    /* 1 */ {"pkgcmd", "/usr/bin/pkgcmd"},
    /* 2 */ {"launch_app", "/usr/bin/launch_app"},
    /* 3 */ {"dlogutil", "/usr/bin/dlogutil"},
    /* 4 */ {"zypper", "/usr/bin/zypper"},
    /* 5 */ {"pkginfo", "/usr/bin/pkginfo"},
    /* 6 */ {"da_command", "/usr/bin/da_command"},
    /* 7 */ {"oprofile", "/usr/bin/oprofile_command"},
    /* 8 */ {"wrt-launcher", "/usr/bin/wrt-launcher"},
    /* end */ {NULL, NULL}
};

struct arg_permit_rule sdk_arg_permit_rule[] = {
    /* 2 */ {"gcove_env1", "^GCOV_PREFIX=((/opt/apps)|(/opt/usr/apps))/[a-zA-Z0-9]{10}/data$", 1},
    /* 2 */ {"gcove_env2", "GCOV_PREFIX_STRIP=0", 0},
    /* 2 */ {"gcove_env3", "LD_LIBRARY_PATH=/home/developer/sdk_tools/gtest/usr/lib:$LD_LIBRARY_PATH", 0},
    /* 2 */ {"gcove_env4", "TIZEN_LAUNCH_MODE=debug", 0},
    /* 2 */ {"da_env1", "LD_PRELOAD=/usr/lib/da_probe_osp.so", 0},
    /* 2 */ {"gcove_arg1", "^\\-\\-gtest_output=xml:((/opt/apps)|(/opt/usr/apps))/[a-zA-Z0-9]{10}/data/[a-zA-Z0-9_\\-]{1,30}\\.xml$", 1},
    /* end */ {NULL, NULL, 0}
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
    int index = -1;
    int i = 0;

    D("cmd processing......: %s\n", arg1);

    cnt = tokenize(arg1, " ", tokens, MAX_TOKENS);
    for (i=0; i<cnt; i++) {
        D("tokenize: %dth: %s\n", i, tokens[i]);
    }
    if (cnt == 0 ) {
        return 0; // just keep going to execute normal commands
    }
    index = is_root_commands(tokens[0]);
    if (index == -1) {
        if (exec_app_standalone(arg1)) {
            ret = 1;
        } else {
            return 0; // just keep going to execute normal commands
        }
    }

    switch (index) {
    case 0: {
        if (cnt == 2) {
            if (verify_app_path(tokens[1])) {
                ret = 1;
            }
        }
        break;
    }
    case 1: {
        ret = 1;
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
        ret = 1;
        break;
    }
    case 6: {
        ret = 1;
        break;
    }
    case 7: {
        ret = 1;
        break;
    }
    case 8: {
        ret = 1;
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
    char buf[PATH_MAX];

    snprintf(buf, sizeof buf, "^((%s)|(%s))/[a-zA-Z0-9]{%d}/bin/[a-zA-Z0-9_\\-]{1,}(\\.exe)?$", APP_INSTALL_PATH_PREFIX1, APP_INSTALL_PATH_PREFIX2, APPID_MAX_LENGTH);
    return regcmp(buf, path);
}

int regcmp(const char* pattern, const char* str) {
    regex_t regex;
    int ret;

    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if(ret){ // not match
        return 0;
    }

    // execute regular expression
    ret = regexec(&regex, str, 0, NULL, 0);
    if(!ret){
        regfree(&regex);
        return 1;
    } else if( ret == REG_NOMATCH ){
        //D("not valid application path\n");
    } else{
        //regerror(ret, &regex, buf, sizeof(buf));
        //D("regex match failed: %s\n", buf);
    }
    regfree(&regex);
    return 0;
}

int env_verify(const char* arg) {
    int i;
    for (i=0; sdk_arg_permit_rule[i].name != NULL; i++) {
        if (sdk_arg_permit_rule[i].expression == 0) {
            if (!strcmp(sdk_arg_permit_rule[i].pattern, arg)) {
                D("success to set %s\n", arg);
                return 1;
            }
        } else if (sdk_arg_permit_rule[i].expression == 1) {
            if (regcmp(sdk_arg_permit_rule[i].pattern, arg)) {
                D("success to set %s\n", arg);
                return 1;
            }
        }
    }
    D("failed to set %s\n", arg);
    return 0;
}

int exec_app_standalone(const char* path) {
    char *tokens[MAX_TOKENS];
    int ret = 0;
    int cnt = 0;
    int flag = 1;
    int i=0;

    cnt = tokenize(path, " ", tokens, MAX_TOKENS);
    for (i=0; i<cnt; i++) {
        D("tokenize: %dth: %s\n", i, tokens[i]);

        if (!strcmp("export", tokens[i])) {
            flag = 0;
            i++;
            if (i>=cnt) break;
            if (env_verify(tokens[i])) {
                flag = 1;
            }
            i++;
            if (i>=cnt) break;
            if (!strcmp("&&", tokens[i])) {
                continue;
            }
        }
        if (flag == 0) {
            // TODO: check evn setting
        }
        // TODO: i length check
        if (!strcmp(tokens[i], GDBSERVER_PATH)) { //gdbserver :11 --attach 2332 (cnt=4,)
            char *gdb_attach_arg_pattern = "^:[1-9][0-9]{2,5} \\-\\-attach [1-9][0-9]{2,5}$";
            int argcnt = cnt-i-1;
            if (argcnt == 3 && !strcmp("--attach", tokens[i+2])) {
                char cmdline[128];
                int pid = 0;
                D("parsing.... debug attach mode\n");
                snprintf(cmdline, sizeof(cmdline), "%s %s %s",tokens[i+1], tokens[i+2], tokens[i+3]);
                if (regcmp(gdb_attach_arg_pattern, cmdline)) {
                    char cmdline[128];
                    pid = atoi(tokens[i+3]);
                    if (pid) {
                        snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);
                        int fd = unix_open(cmdline, O_RDONLY);
                        if (fd) {
                            if(read_line(fd, cmdline, sizeof(cmdline))) {
                                if (set_smack_rules_for_gdbserver(cmdline, 1)) {
                                    ret = 1;
                                }
                            }
                            sdb_close(fd);
                        }
                    }
                }
            }
            if (argcnt >= 2 && verify_app_path(tokens[i+2])) {
                D("parsing.... debug run as mode\n");
                if (set_smack_rules_for_gdbserver(tokens[i+2], 0)) {
                    ret = 1;
                }
            }
            D("finished debug launch mode\n");
        } else {
            if (verify_app_path(tokens[i])) {
                char *path = tokens[i];
                char *appid = NULL;
                int rc = smack_lgetlabel(path, &appid, SMACK_LABEL_ACCESS);
                if (rc == 0 && appid != NULL) {
                    if (smack_set_label_for_self(appid) != -1) {
                        D("set smack lebel [%s] appid to %s\n", appid, SMACK_LEBEL_SUBJECT_PATH);
                        apply_app_process();
                        ret = 1;
                    } else {
                        D("unable to open %s due to %s\n", SMACK_LEBEL_SUBJECT_PATH, strerror(errno));
                    }
                    free(appid);
                }
                D("standalone launch\n");
            }
        }
        // TODO: verify arguments
        break;
    }

    if (cnt) {
        free_strings(tokens, cnt);
    }
    return ret;
}

/**
 * free after use it
 */
char* clone_gdbserver_label_from_app(const char* app_path) {
    char *new_appid = NULL;
    char appid[APPID_MAX_LENGTH+1];
    char *buffer = NULL;

    if (!verify_app_path(app_path)) {
        D("not be able to access %s\n", app_path);
        return NULL;
    }

    int rc = smack_lgetlabel(app_path, &buffer, SMACK_LABEL_ACCESS);

    if (rc == 0 && buffer != NULL && strlen(buffer) == APPID_MAX_LENGTH) {
        strcpy(appid, buffer);
        free(buffer);
    } else {
        strcpy(appid, "_");
    }
    new_appid = (char *)malloc(sizeof(appid)+1);
    strncpy(new_appid, appid, APPID_MAX_LENGTH);
    // Do not label to gdbserver executable
/*
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
*/
    return new_appid;
}

int set_smack_rules_for_gdbserver(const char* apppath, int mode) {
    // FIXME: set gdbfolder to 755 also
    if(sdb_chmod(GDBSERVER_PATH, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH, 1) < 0)
    {
        D("unable to set 755 to %s", GDBSERVER_PATH);
    }

    // in case of debug as mode
    char *new_appid = clone_gdbserver_label_from_app(apppath);
    if (new_appid != NULL) {
        if (smack_set_label_for_self(new_appid) != -1) {
            D("set smack lebel [%s] appid to %s\n", new_appid, SMACK_LEBEL_SUBJECT_PATH);
            // apply app precess only if not attach mode
            if (mode == 0) {
                apply_app_process();
            }
        } else {
            D("unable to open %s due to %s\n", SMACK_LEBEL_SUBJECT_PATH, strerror(errno));
        }
        free(new_appid);
        return 1;
    }
    // TODO: in case of attach mode
    return 0;
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
    gid_t groups[APP_GROUPS_MAX]={0,};
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
