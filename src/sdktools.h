#ifndef _SDKTOOLS_H
#define _SDKTOOLS_H

#ifdef __cplusplus
extern "C" {
#endif

struct sudo_command
{
  const char *command;
  const char *path;
  //const char *arguments;
  //const char *regx;
  //int   permission; /* 0: root, 1: developer, 2: app*/
};


struct arg_permit_rule
{
    const char *name;
    const char *pattern;
    int expression; // 0:compare, 1: regx
};

#define SDK_LAUNCH_PATH                         "/usr/sbin/sdk_launch"
#define APP_INSTALL_PATH_PREFIX1                "/opt/apps"
#define APP_INSTALL_PATH_PREFIX2                "/opt/usr/apps"
#define GDBSERVER_PATH                          "/home/developer/sdk_tools/gdbserver/gdbserver"
#define GDBSERVER_PLATFORM_PATH                 "/home/developer/sdk_tools/gdbserver-platform/gdbserver"
#define SMACK_LEBEL_SUBJECT_PATH                "/proc/self/attr/current"
#define SMACK_SYNC_FILE_LABEL                   "*"
#define APP_GROUPS_MAX                          100
#define APP_GROUP_LIST                          "/usr/share/privilege-control/app_group_list"
#define APPID_MAX_LENGTH                        50
#define SDBD_LABEL_NAME                         "sdbd"
#define SDK_HOME_LABEL_NAME                     "sdbd::home"

int verify_root_commands(const char *arg1);
int verify_app_path(const char* path);
int regcmp(const char* pattern, const char* str);
int exec_app_standalone(const char* path);
char* clone_gdbserver_label_from_app(const char* app_path);
int set_smack_rules_for_gdbserver(const char* apppath, int mode);
void apply_app_process();
void set_appuser_groups(void);
int is_root_commands(const char *command);
int apply_sdb_rules(const char* subject, const char* object, const char* access_type);
int is_pkg_file_path(const char* path);

#ifdef __cplusplus
}
#endif

#endif
