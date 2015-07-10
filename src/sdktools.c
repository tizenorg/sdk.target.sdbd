#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/smack.h>

#include "sysdeps.h"
#include "sdktools.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "sdb.h"
#include "sdktools.h"
#include "strutils.h"
#include "fileutils.h"
#include "utils.h"

struct sudo_command root_commands[] = {
    /* 0 */ {"da_command", "/usr/bin/da_command"},
    /* 1 */ {"profile", "/usr/bin/profile_command"},
    /* 2 */ {"rm1", "rm"},
    /* 3 */ {"rm2", "/bin/rm"},
    /* end */ {NULL, NULL}
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
        return 0; // just keep going to execute normal commands
    }

    switch (index) {
    case 0: { // in case of da_command
        ret = 0;
        if (!is_cmd_suffix_denied(arg1)) {
            ret = 1;
        }
        // this is exception to allow suffix
        if (cnt == 5 && !strcmp(tokens[1], "process")
                && !strcmp(tokens[2], "|")
                && !strcmp(tokens[3], "grep")
                && !is_cmd_suffix_denied(tokens[4])) {
                ret = 1;
        }
        break;
    }
    case 1: { // in case of oprofile_command
        ret = 0;
        if (!is_cmd_suffix_denied(arg1)) {
            ret = 1;
        }
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
                free(appid);
            }
            D("standalone launch for valgrind\n");
        }

        break;
    }
    case 2:
    case 3:
    { // in case of rm to remove the temporary package file
        if (is_cmd_suffix_denied(arg1)) {
            ret = 0;
            break;
        }
        if (is_pkg_file_path(tokens[1])) {
            ret = 1;
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
