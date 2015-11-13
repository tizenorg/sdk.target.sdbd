#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <sys/smack.h>
#include "smack.h"
#include "sysdeps.h"
#include "sdktools.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "sdb.h"
#include "sdktools.h"
#include "strutils.h"
#include "fileutils.h"
<<<<<<< HEAD

struct sudo_command root_commands[] = {
    /* 0 */ {"killall", "/usr/bin/killall"},
    /* 1 */ {"zypper", "/usr/bin/zypper"},
    /* 2 */ {"da_command", "/usr/bin/da_command"},
    /* 3 */ {"oprofile", "/usr/bin/oprofile_command"},
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

void init_sdk_arg_permit_rule_pattern(void)
{
    asprintf(&sdk_arg_permit_rule[0].pattern, "^GCOV_PREFIX=((%s)|(%s))/[a-zA-Z0-9]{10}/data$", APP_INSTALL_PATH_PREFIX1, APP_INSTALL_PATH_PREFIX2);
    asprintf(&sdk_arg_permit_rule[1].pattern, "GCOV_PREFIX_STRIP=0");
    asprintf(&sdk_arg_permit_rule[2].pattern, "LD_LIBRARY_PATH=%s/gtest/usr/lib:$LD_LIBRARY_PATH", DEV_INSTALL_PATH_PREFIX, APP_INSTALL_PATH_PREFIX2);
    asprintf(&sdk_arg_permit_rule[3].pattern, "TIZEN_LAUNCH_MODE=debug");
    asprintf(&sdk_arg_permit_rule[4].pattern, "LD_PRELOAD=/usr/lib/da_probe_osp.so", DEV_INSTALL_PATH_PREFIX, APP_INSTALL_PATH_PREFIX2);
    asprintf(&sdk_arg_permit_rule[5].pattern, "^\\-\\-gtest_output=xml:((%s)|(%s))/[a-zA-Z0-9]{10}/data/[a-zA-Z0-9_\\-]{1,30}\\.xml$", APP_INSTALL_PATH_PREFIX1, APP_INSTALL_PATH_PREFIX2);
}


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
=======
#include "utils.h"

struct sudo_command root_commands[] = {
    /* 0 */
    { "profile", "/usr/bin/profile_command",
        { "killmanager",
        "runmanager",
        "findunittest",
        "process",
        "getversion",
        "killvalgrind",
        "getprobemap",
        NULL
        }
    },
    /* end */
    { NULL, NULL, NULL }
};

static struct command_suffix
{
    const char *name; // comments for human
    const char *suffix; //pattern
};

static struct command_suffix CMD_SUFFIX_DENY_KEYWORD[] = {
        /* 0 */   {"pipe", "|"},
        /* 1 */   {"redirect", ">"},
        /* 2 */   {"semicolon", ";"}, // separated list is executed
        /* 3 */   {"and", "&"},
        /* 4 */   {"command_substitution1", "$"},
        /* 5 */   {"command_substitution2", "`"},
        /* end */ {NULL, NULL}
};

/**
 * return 1 if the arg is arrowed, otherwise 0 is denied
 */
static int is_cmd_suffix_denied(const char* arg) {
    int i;

    for (i=0; CMD_SUFFIX_DENY_KEYWORD[i].name != NULL; i++) {
        if (strstr(arg, CMD_SUFFIX_DENY_KEYWORD[i].suffix) != NULL) {
            D("cmd suffix denied:%s\n", arg);
            return 1;
        }
    }
    D("cmd suffix arrowed:%s\n", arg);
    return 0;
}

static int get_application_install_path(char* pkg_path) {
    FILE *fp = NULL;
    char ret_str[PATH_MAX+64] = {0,};
    int len = 0;

    fp = popen("/usr/bin/pkgcmd -a", "r");
    if (fp == NULL) {
        D("failed : popen pkgcmd -a\n");
        return 0;
    }
    if (!fgets(ret_str, PATH_MAX+64, fp)) {
        D("failed : fgets pkgcmd -a\n");
        pclose(fp);
        return 0;
    }
    pclose(fp);

    len = strlen(ret_str);
    while(ret_str[--len]=='\n');
    ret_str[len + 1] = '\0';

    if (sscanf(ret_str, "Tizen Application Installation Path: %s", pkg_path) != 1) {
        D("failed : parsing fail (str:%s)\n", ret_str);
        return 0;
    }

    D("Tizen install path: %s\n", pkg_path);
    return 1;
}

int is_pkg_file_path(const char* path) {
    regex_t regex;
    int ret;
    char pkg_path[PATH_MAX] = {0,};
    char pkg_path_regx[PATH_MAX+64] = {0,};

    if (!get_application_install_path(pkg_path)) {
        D("failed to get application install path\n");
        return 0;
    }

    snprintf(pkg_path_regx, sizeof(pkg_path_regx),
        "^.*(%s/tmp/)+[a-zA-Z0-9_\\-\\.]*\\.(wgt|tpk),*[0-9]*$", pkg_path);

    ret = regcomp(&regex, pkg_path_regx, REG_EXTENDED);
    if (ret){
        D("failed : recomp (error:%d)\n", ret);
        return 0;
    }

    ret = regexec(&regex, path, 0, NULL, 0);
    regfree(&regex);

    if (ret){
        D("This path is NOT package file: %s\n", path);
        return 0;
    }

    D("This path is temporary package file: %s\n", path);
>>>>>>> tizen_2.4
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
<<<<<<< HEAD
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
        if (!strcmp(tokens[1], "valgrind") && cnt >= 3) {
            char *appid = NULL;
            // the tokens[2] should be apppath
            int rc = smack_lgetlabel(tokens[2], &appid, SMACK_LABEL_ACCESS);
            if (rc == 0 && appid != NULL) {
                if (apply_sdb_rules(SDBD_LABEL_NAME, appid, "rwax") < 0) {
                    D("unable to set %s %s rules\n", SDBD_LABEL_NAME, appid);
                } else {
                    D("apply rule to '%s %s rwax' rules\n", SDBD_LABEL_NAME, appid);
                }
                if (apply_sdb_rules(appid, SDBD_LABEL_NAME, "rwax") < 0) {
                    D("unable to set %s %s rules\n", appid, SDBD_LABEL_NAME);
                } else {
                    D("apply rule to '%s %s rwax' rules\n", appid, SDBD_LABEL_NAME);
                }
                //apply_app_process();

                free(appid);
            }
            D("standalone launch for valgrind\n");
        }

        ret = 1;
=======
        return 0; // just keep going to execute normal commands
    }

    switch (index) {
    // in case of profile_command
    case 0: {
        ret = 0;
        if (!is_cmd_suffix_denied(arg1) && (cnt == 2)) {
            // check if command is used with permitted arguments
            for (i = 0; root_commands[0].arguments[i] != NULL; i++) {
                if (!strncmp(tokens[1], root_commands[0].arguments[i], strlen(tokens[1]))){
                    D("found permitted arguments :%s\n", tokens[1]);
                    ret = 1;
                    break;
                }

            }
            if (ret == 0) {
                D("not found permitted arguments :%s\n", tokens[1]);
            }
        }
>>>>>>> tizen_2.4
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

<<<<<<< HEAD
int verify_app_path(const char* path) {
    char buf[PATH_MAX];

    snprintf(buf, sizeof buf, "^((%s)|(%s))/[a-zA-Z0-9]{%d}/bin/[a-zA-Z0-9_\\-]{1,}(\\.exe)?$", APP_INSTALL_PATH_PREFIX1, APP_INSTALL_PATH_PREFIX2, 10);
    int reg_cmp = regcmp(buf, path);

    return reg_cmp;
}

=======
>>>>>>> tizen_2.4
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

<<<<<<< HEAD
int env_verify(const char* arg) {
    int i;
    init_sdk_arg_permit_rule_pattern();
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
    for (i = 0; i <= 6; i++){
       free(sdk_arg_permit_rule[i].pattern);
    }
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

        if(!strcmp(tokens[i], SDK_LAUNCH_PATH)) {
            int debug = 0;
            int pid = 0;
            char* pkg_id = NULL;
            char* executable = NULL;
            ++i;
            while( i < cnt ) {
                if(!strcmp(tokens[i], "-attach")) {
                    if(++i < cnt) {
                        char* pid_pattern = "[1-9][0-9]{2,5}";
                        if (regcmp(pid_pattern, tokens[i])) {
                            pid = atoi(tokens[i]);
                        }
                    }
                }
                else if(!strcmp(tokens[i], "-p")) {
                    if(++i < cnt) {
                        pkg_id = tokens[i];
                    }
                }
                else if(!strcmp(tokens[i], "-e")) {
                    if(++i < cnt) {
                        executable = tokens[i];
                    }
                }
                i++;
            }
            if(pid > 0) {
                char cmdline[128];
                if (pid) {
                    snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);
                    int fd = unix_open(cmdline, O_RDONLY);
                    if (fd > 0) {
                        if(read_line(fd, cmdline, sizeof(cmdline))) {
                            if (set_smack_rules_for_gdbserver(cmdline, 1)) {
                                ret = 1;
                            }
                        }
                        sdb_close(fd);
                    }
                }
            }
            break;
        }
        // TODO: i length check
        else if (!strcmp(tokens[i], GDBSERVER_PATH) || !strcmp(tokens[i], GDBSERVER_PLATFORM_PATH)) { //gdbserver :11 --attach 2332 (cnt=4,)
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
                        if (fd > 0) {
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
            else if (argcnt >= 2) {
                if(should_drop_privileges() == 0 || verify_app_path(tokens[i+2])) {
                    D("parsing.... debug run as mode\n");
                    if (set_smack_rules_for_gdbserver(tokens[i+2], 0)) {
                        ret = 1;
                    }
                }
            }
            D("finished debug launch mode\n");
        } else {
            if (verify_app_path(tokens[i])) {
                char *path = tokens[i];
                char *appid = NULL;
                int rc = smack_lgetlabel(path, &appid, SMACK_LABEL_ACCESS);
                if (rc == 0 && appid != NULL) {
                    if (apply_sdb_rules(SDBD_LABEL_NAME, appid, "rwax") < 0) {
                        D("unable to set sdbd rules to %s %s rwax\n", SDBD_LABEL_NAME, appid);
                    } else {
                        D("set sdbd rules to %s %s rwax\n", SDBD_LABEL_NAME, appid);
                    }
                    if (apply_sdb_rules(appid, SDBD_LABEL_NAME, "rwax") < 0) {
                        D("unable to set sdbd rules to %s %s rwax\n", appid, SDBD_LABEL_NAME);
                    } else {
                        D("set sdbd rules to %s %s rwax\n", appid, SDBD_LABEL_NAME);
                    }
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

#if 0
    if (!verify_app_path(app_path)) {
        D("not be able to access %s\n", app_path);
        return NULL;
    }
#endif

    int rc = smack_lgetlabel(app_path, &buffer, SMACK_LABEL_ACCESS);

    if (rc == 0 && buffer != NULL) {
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
        if (apply_sdb_rules(SDBD_LABEL_NAME, new_appid, "w") < 0) {
            D("unable to set sdbd rules\n");
        }
        if (apply_sdb_rules(new_appid, SDK_HOME_LABEL_NAME, "rx") < 0) {
            D("unable to set sdbd home rules\n");
        }
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

int apply_sdb_rules(const char* subject, const char* object, const char* access_type) {
    struct smack_accesses *rules = NULL;
    int ret = 0;

    if (smack_accesses_new(&rules))
        return -1;

    if (smack_accesses_add(rules, subject, object, access_type)) {
        smack_accesses_free(rules);
        return -1;
    }

    ret = smack_accesses_apply(rules);
    smack_accesses_free(rules);

    return ret;
}

void apply_app_process() {
    set_appuser_groups();

    if (setgid(SID_APP) != 0) {
        //fprintf(stderr, "set group id failed errno: %d\n", errno);
        exit(1);
    }

    if (setuid(SID_APP) != 0) {
        //fprintf(stderr, "set user id failed errno: %d\n", errno);
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
            sdb_close(fd);
           fprintf(stderr, "set groups failed errno: %d\n", errno);
           exit(1);
        }
    }
    sdb_close(fd);
}

=======
>>>>>>> tizen_2.4
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
