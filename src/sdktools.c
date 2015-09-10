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
