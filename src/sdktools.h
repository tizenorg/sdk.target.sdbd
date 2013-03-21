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

#define APP_INSTALL_PATH_PREFIX1                "/opt/apps"
#define APP_INSTALL_PATH_PREFIX2                "/usr/apps"
#define GDBSERVER_PATH                          "/home/developer/sdk_tools/gdbserver/gdbserver"
#define SMACK_LEBEL_SUBJECT_PATH                "/proc/self/attr/current"
#define APP_GROUPS_MAX                          100
#define APP_GROUP_LIST                          "/usr/share/privilege-control/app_group_list"
#define APPID_MAX_LENGTH                        10

int verify_commands(const char *arg1);
int verify_root_commands(const char *arg1);
int verify_app_path(const char* path);
int get_appid(const char* path, char* appid);
char* clone_gdbserver_label_from_app(const char* app_path);
void apply_app_process();
void set_appuser_groups(void);
int is_root_commands(const char *command);

#ifdef __cplusplus
}
#endif

#endif
