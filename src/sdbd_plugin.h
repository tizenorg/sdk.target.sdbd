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

#ifndef __SDBD_PLUGIN_H
#define __SDBD_PLUGIN_H

#include <string.h>

/* plugin commands */
#define SDBD_CMD_PLUGIN_CAP             "plugin_capability"
#define SDBD_CMD_VERIFY_SHELLCMD        "verify_shell_cmd"
#define SDBD_CMD_CONV_SHELLCMD          "convert_shell_cmd"
#define SDBD_CMD_VERIFY_PEERIP          "verify_peer_ip"
#define SDBD_CMD_VERIFY_LAUNCH          "verify_sdbd_launch"
#define SDBD_CMD_VERIFY_ROOTCMD         "verify_root_cmd"

/* plugin capabilities */
#define SDBD_CAP_TYPE_SECURE            "secure_protocol_support"
#define SDBD_CAP_TYPE_INTER_SHELL       "interactive_shell_support"
#define SDBD_CAP_TYPE_FILESYNC          "file_sync_support"
#define SDBD_CAP_TYPE_USBPROTO          "usb_protocol_support"
#define SDBD_CAP_TYPE_SOCKPROTO         "socket_protocol_support"
#define SDBD_CAP_TYPE_ROOTONOFF         "root_onoff_support"
#define SDBD_CAP_TYPE_PLUGIN_VER        "sdbd_plugin_version"
#define SDBD_CAP_TYPE_PRODUCT_VER       "product_version"
/* capability return string */
#define SDBD_CAP_RET_ENABLED            "enabled"
#define SDBD_CAP_RET_DISABLED           "disabled"
#define SDBD_CAP_RET_PUSH               "push"
#define SDBD_CAP_RET_PULL               "pull"
#define SDBD_CAP_RET_PUSHPULL           "pushpull"

/* verification return string */
#define SDBD_RET_VALID                  "valid"
#define SDBD_RET_INVALID                "invalid"

/* proc interface return value */
#define SDBD_PLUGIN_RET_SUCCESS         (0)
#define SDBD_PLUGIN_RET_FAIL            (-1)
#define SDBD_PLUGIN_RET_NOT_SUPPORT     (-2)

/* utility macro */
#define SDBD_CMP_CMD(cmd, type)                             \
    ((strlen(cmd) == strlen(SDBD_CMD_##type)                \
    && !strncmp(cmd, SDBD_CMD_##type, strlen(cmd)))?1:0)

#define SDBD_CMP_CAP(cap, type)                             \
    ((strlen(cap) == (strlen(SDBD_CAP_TYPE_##type))         \
    && !strncmp(cap, SDBD_CAP_TYPE_##type, strlen(cap)))?1:0)

/* out parameter structure */
#define SDBD_SHELL_CMD_MAX      4096
#define SDBD_PLUGIN_OUTBUF_MAX  4096
typedef struct sdbd_plugin_param {
    unsigned int len;
    char *data;
} sdbd_plugin_param;

/* log system */
// 1. set the environment value. : SDB_TRACE=all
// 2. restart the sdbd deamon.
// 3. log is output to the /tmp/sdbd-[date].txt
#define SDBD_PLUGIN_LOG(...)                \
        fprintf(stderr, "%s::%s():",        \
                __FILE__, __FUNCTION__);    \
        fprintf(stderr, __VA_ARGS__);

#endif
