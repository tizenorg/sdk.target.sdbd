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
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <utime.h>
#include <regex.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/smack.h>
#include <security-server.h>
#include "sysdeps.h"

#define TRACE_TAG  TRACE_SYNC
#include "sdb.h"
#include "sdbd_plugin.h"
#include "file_sync_service.h"
#include "sdktools.h"
#include "utils.h"

#define SYNC_TIMEOUT 15

/* The typical default value for the umask is S_IWGRP | S_IWOTH (octal 022).
 * Before use the DIR_PERMISSION, the process umask value should be set 0 using umask().
 */
#define DIR_PERMISSION 0777

static void set_syncfile_smack_label(char *src) {
    char *label_transmuted = NULL;
    char *label = NULL;
    char *src_chr = strrchr(src, '/');
    int pos = src_chr - src + 1;
    char dirname[512];

    snprintf(dirname, pos, "%s", src);

    //D("src:[%s], dirname:[%s]\n", src, dirname);
    int rc = smack_getlabel(dirname, &label_transmuted, SMACK_LABEL_TRANSMUTE);

    if (rc == 0 && label_transmuted != NULL) {
        if (!strcmp("TRUE", label_transmuted)) {
            rc = smack_getlabel(dirname, &label, SMACK_LABEL_ACCESS);
            if (rc == 0 && label != NULL) {
                rc = security_server_label_access(src, label);
                if (rc != SECURITY_SERVER_API_SUCCESS) {
                    D("unable to set sync file smack label %s due to %d\n", label, errno);
                }
                free(label);
            }
        } else{
            D("fail to set label, is it transmuted?:%s\n", label_transmuted);
        }
        free(label_transmuted);
    } else {
        rc = security_server_label_access(src, SMACK_SYNC_FILE_LABEL);
        if (rc != SECURITY_SERVER_API_SUCCESS) {
            D("unable to set sync file smack label %s due to %d\n", SMACK_SYNC_FILE_LABEL, errno);
        }
    }
}

static int sync_send_label_notify(int s, const char *path, int success)
{
    char buffer[512] = {0,};
    snprintf(buffer, sizeof(buffer), "%d:%s", success, path);

    int len = sdb_write(s, buffer, sizeof(buffer));

    return len;
}

static void sync_read_label_notify(int s)
{
    char buffer[512 + 1] = {0,};

    while (1) {
        int len = sdb_read(s, buffer, sizeof(buffer) - 1);
        if (len < 0) {
            D("sync notify read errno:%d\n", errno);
            exit(-1);
        }

        if (buffer[0] == '0') {
            D("sync notify child process exit\n");
            exit(-1);
        }
        buffer[len] = '\0';
        char *path = buffer;
        path++;
        path++;
        set_syncfile_smack_label(path);
    }
}

static int mkdirs(int noti_fd, char *name)
{
    int ret;
    char *x = name + 1;

    if(name[0] != '/') {
        return -1;
    }

    for(;;) {
        x = sdb_dirstart(x);
        if(x == 0) {
            return 0;
        }
        *x = 0;

        ret = sdb_mkdir(name, DIR_PERMISSION);
        if (ret == 0) {
            sync_send_label_notify(noti_fd, name, 1);
        }
        if((ret < 0) && (errno != EEXIST)) {
            D("mkdir(\"%s\") -> errno:%d\n", name, errno);
            *x = '/';
            return ret;
        }
        *x++ = '/';
    }
    return 0;
}

static int do_stat(int s, const char *path)
{
    syncmsg msg;
    struct stat st;

    msg.stat.id = ID_STAT;

    /* follow link */
    if(stat(path, &st)) {
        msg.stat.mode = 0;
        msg.stat.size = 0;
        msg.stat.time = 0;
        D("failed to stat %s due to: errno:%d\n", path, errno);
    } else {
        msg.stat.mode = htoll(st.st_mode);
        msg.stat.size = htoll(st.st_size);
        msg.stat.time = htoll(st.st_mtime);
    }

    return writex(s, &msg.stat, sizeof(msg.stat));
}

static int do_list(int s, const char *path)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    syncmsg msg;
    int len;

    char tmp[1024 + 256 + 1];
    char *fname;

    char dirent_buffer[ sizeof(struct dirent) + 260 + 1 ]  = {0,};
    struct dirent *dirent_r = (struct dirent*)dirent_buffer;

    len = strlen(path);
    memcpy(tmp, path, len);
    tmp[len] = '/';
    fname = tmp + len + 1;

    msg.dent.id = ID_DENT;

    d = opendir(path);
    if(d == NULL) {
        D("failed to open dir due to: errno:%d\n", errno);
        goto done;
    }

    while((readdir_r(d, dirent_r, &de) == 0) && de) {
        int len = strlen(de->d_name);

            /* not supposed to be possible, but
               if it does happen, let's not buffer overrun */
        if(len > 256) {
            continue;
        }

        s_strncpy(fname, de->d_name, sizeof tmp);
        if(lstat(tmp, &st) == 0) {
            msg.dent.mode = htoll(st.st_mode);
            msg.dent.size = htoll(st.st_size);
            msg.dent.time = htoll(st.st_mtime);
            msg.dent.namelen = htoll(len);

            if(writex(s, &msg.dent, sizeof(msg.dent)) ||
               writex(s, de->d_name, len)) {
                closedir(d);
                return -1;
            }
        }
    }

    closedir(d);

done:
    msg.dent.id = ID_DONE;
    msg.dent.mode = 0;
    msg.dent.size = 0;
    msg.dent.time = 0;
    msg.dent.namelen = 0;
    return writex(s, &msg.dent, sizeof(msg.dent));
}

static int fail_message(int s, const char *reason)
{
    syncmsg msg;
    int len = strlen(reason);

    D("sync: failure: %s\n", reason);

    msg.data.id = ID_FAIL;
    msg.data.size = htoll(len);
    if(writex(s, &msg.data, sizeof(msg.data)) ||
       writex(s, reason, len)) {
        return -1;
    } else {
        return 0;
    }
}

static int fail_errno(int s)
{
	char buf[512];

	strerror_r(s, buf, sizeof(buf));

    return fail_message(s, buf);
}

// FIXME: should get the following paths with api later but, do it for simple and not having dependency on other packages
#define VAR_ABS_PATH        "/opt/var"
#define VSM_ZONE_PATH       "/var/lib/lxc/"
#define VSM_ZONE_ROOTFS     "rootfs/"
#define CMD_MEDIADB_UPDATE "/usr/bin/mediadb-update"
#define MEDIA_CONTENTS_PATH1 "/opt/media"
#define MEDIA_CONTENTS_PATH2 "/opt/usr/media"
#define MEDIA_CONTENTS_PATH3 "/opt/storage/sdcard"

static void sync_mediadb(char *path) {
	int is_inzone = 0;

    if (access(CMD_MEDIADB_UPDATE, F_OK) != 0) {
        D("%s: command not found\n", CMD_MEDIADB_UPDATE);
        return;
    }

    if (strstr(path, VAR_ABS_PATH) == path) {
        path += 4;
    }
    if (strstr(path, VSM_ZONE_PATH) == path) {
        path += sizeof(VSM_ZONE_PATH) - 1;
        while (*(path++) != '/');
        while (*(path++) == '/');
        path--;

		if (strstr(path, VSM_ZONE_ROOTFS) == path) {
			path += sizeof(VSM_ZONE_ROOTFS) - 1;
			while (*(path++) == '/');
			path -= 2;
			is_inzone = 1;
        }
     }

    if (strstr(path, MEDIA_CONTENTS_PATH1) != NULL) {
    	if (is_inzone) {
    	    char *arg_list[] = {CMD_ATTACH, "-f", "--", CMD_MEDIADB_UPDATE, "-r", MEDIA_CONTENTS_PATH1, NULL};
    	    spawn(CMD_ATTACH, arg_list);
    	} else {
    	    char *arg_list[] = {CMD_MEDIADB_UPDATE, "-r", MEDIA_CONTENTS_PATH1, NULL};
            spawn(CMD_MEDIADB_UPDATE, arg_list);
            D("media db update done to %s\n", MEDIA_CONTENTS_PATH1);
    	}
    } else if (strstr(path, MEDIA_CONTENTS_PATH2) != NULL) {
    	if (is_inzone) {
    	    char *arg_list[] = {CMD_ATTACH, "-f", "--", CMD_MEDIADB_UPDATE, "-r", MEDIA_CONTENTS_PATH2, NULL};
    	    spawn(CMD_ATTACH, arg_list);
    	} else {
    	    char *arg_list[] = {CMD_MEDIADB_UPDATE, "-r", MEDIA_CONTENTS_PATH2, NULL};
    	    spawn(CMD_MEDIADB_UPDATE, arg_list);
    	}
        D("media db update done to %s\n", MEDIA_CONTENTS_PATH2);
    } else if (strstr(path, MEDIA_CONTENTS_PATH3) != NULL) {
    	if (is_inzone) {
    	    char *arg_list[] = {CMD_ATTACH, "-f", "--", CMD_MEDIADB_UPDATE, "-r", MEDIA_CONTENTS_PATH3, NULL};
    	    spawn(CMD_ATTACH, arg_list);
    	} else {
    	    char *arg_list[] = {CMD_MEDIADB_UPDATE, "-r", MEDIA_CONTENTS_PATH3, NULL};
    	    spawn(CMD_MEDIADB_UPDATE, arg_list);
    	}
        D("media db update done to %s\n", MEDIA_CONTENTS_PATH3);
    }
    return;
}

static int handle_send_file(int s, int noti_fd, char *path, mode_t mode, char *buffer)
{
    syncmsg msg;
    unsigned int timestamp = 0;
    int fd;

    fd = sdb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if(fd < 0 && errno == ENOENT) {
        mkdirs(noti_fd, path);
        fd = sdb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    }
    if(fd < 0 && errno == EEXIST) {
        fd = sdb_open_mode(path, O_WRONLY, mode);
    }
    if(fd < 0) {
        if(fail_errno(s))
            return -1;
        fd = -1;
    }
    for(;;) {
        unsigned int len;

        if(readx(s, &msg.data, sizeof(msg.data))) {
            goto fail;
        }
        if(msg.data.id != ID_DATA) {
            if(msg.data.id == ID_DONE) {
                timestamp = ltohl(msg.data.size);
                break;
            }
            fail_message(s, "invalid data message");
            goto fail;
        }
        len = ltohl(msg.data.size);
        if(len > SYNC_DATA_MAX) {
            fail_message(s, "oversize data message");
            goto fail;
        }
        if(readx(s, buffer, len)) {
            D("read failed due to unknown reason\n");
            goto fail;
        }

        if(fd < 0) {
            continue;
        }
        if(writex(fd, buffer, len)) {
            int saved_errno = errno;
            sdb_close(fd);
            sdb_unlink(path);
            fd = -1;
            errno = saved_errno;
            if(fail_errno(s)) return -1;
        }
    }

    if(fd >= 0) {
        struct utimbuf u;
        sdb_close(fd);
        u.actime = timestamp;
        u.modtime = timestamp;
        utime(path, &u);

        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if(writex(s, &msg.status, sizeof(msg.status)))
            return -1;
        // flush file system buffers due to N_SE-22305
        sync();
    } else {
        D("sync error: %d!!!\n", fd);
        return -1;
    }
    sync_send_label_notify(noti_fd, path, 1);
    sync_mediadb(path);
    return 0;

fail:
    if(fd >= 0)
        sdb_close(fd);
    sdb_unlink(path);
    return -1;
}

#ifdef HAVE_SYMLINKS
static int handle_send_link(int s, int noti_fd, char *path, char *buffer)
{
    syncmsg msg;
    unsigned int len;
    int ret;

    if(readx(s, &msg.data, sizeof(msg.data)))
        return -1;

    if(msg.data.id != ID_DATA) {
        fail_message(s, "invalid data message: expected ID_DATA");
        return -1;
    }

    len = ltohl(msg.data.size);
    if(len > SYNC_DATA_MAX) {
        fail_message(s, "oversize data message");
        return -1;
    }
    if(readx(s, buffer, len))
        return -1;

    ret = symlink(buffer, path);
    if(ret && errno == ENOENT) {
        mkdirs(noti_fd, path);
        ret = symlink(buffer, path);
    }
    if(ret) {
        fail_errno(s);
        return -1;
    }

    if(readx(s, &msg.data, sizeof(msg.data)))
        return -1;

    if(msg.data.id == ID_DONE) {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if(writex(s, &msg.status, sizeof(msg.status)))
            return -1;
    } else {
        fail_message(s, "invalid data message: expected ID_DONE");
        return -1;
    }

    return 0;
}
#endif /* HAVE_SYMLINKS */

static int is_support_push()
{
    return (!strncmp(g_capabilities.filesync_support, SDBD_CAP_RET_PUSHPULL, strlen(SDBD_CAP_RET_PUSHPULL))
            || !strncmp(g_capabilities.filesync_support, SDBD_CAP_RET_PUSH, strlen(SDBD_CAP_RET_PUSH)));
}

static int is_support_pull()
{
    return (!strncmp(g_capabilities.filesync_support, SDBD_CAP_RET_PUSHPULL, strlen(SDBD_CAP_RET_PUSHPULL))
            || !strncmp(g_capabilities.filesync_support, SDBD_CAP_RET_PULL, strlen(SDBD_CAP_RET_PULL)));
}

static int do_send(int s, int noti_fd, char *path, char *buffer)
{
    char *tmp;
    mode_t mode;
    int is_link, ret;

    // Check the capability for file push support.
    if(!is_support_push()) {
        fail_message(s, "NO support file push.");
        return -1;
    }

    tmp = strrchr(path,',');
    if(tmp) {
        *tmp = 0;
        errno = 0;
        mode = strtoul(tmp + 1, NULL, 0);
#ifndef HAVE_SYMLINKS
        is_link = 0;
#else
        is_link = S_ISLNK(mode);
#endif
        // extracts file permission from stat.mode. (ex 100644 & 0777 = 644);
        mode &= 0777; // combination of (S_IRWXU | S_IRWXG | S_IRWXO)
        mode |= S_IWOTH; // SDK requirement from N_SE-43337
    }
    if(!tmp || errno) {
        mode = 0644; // set default permission value in most of unix system.
        is_link = 0;
    }
    if (is_pkg_file_path(path)) {
        mode = 0644;
        is_link = 0;
    }

    // sdb does not allow to check that file exists or not. After deleting old file and creating new file again unconditionally.
    sdb_unlink(path);


#ifdef HAVE_SYMLINKS
    if(is_link)
        ret = handle_send_link(s, noti_fd, path, buffer);
    else {
#else
    {
#endif
        /* copy user permission bits to "group" and "other" permissions.
         * ex) 0644 file will be created copied 0666 file.
         * the following 2 lines should be commented if sdb process has been set to umask 0.
         */

        //mode |= ((mode >> 3) & 0070);
        //mode |= ((mode >> 3) & 0007);
        ret = handle_send_file(s, noti_fd, path, mode, buffer);
    }

    return ret;
}

static int do_recv(int s, const char *path, char *buffer)
{
    syncmsg msg;
    int fd, r;

    // Check the capability for file push support.
    if (!is_support_pull()) {
        fail_message(s, "NO support file pull.");
        return -1;
    }

    fd = sdb_open(path, O_RDONLY);
    if(fd < 0) {
        if(fail_errno(s)) return -1;
        return 0;
    }

    msg.data.id = ID_DATA;
    for(;;) {
        r = sdb_read(fd, buffer, SYNC_DATA_MAX);
        if(r <= 0) {
            if(r == 0) break;
            if(errno == EINTR) continue;
            r = fail_errno(s);
            sdb_close(fd);
            return r;
        }
        msg.data.size = htoll(r);
        if(writex(s, &msg.data, sizeof(msg.data)) ||
           writex(s, buffer, r)) {
            sdb_close(fd);
            return -1;
        }
    }

    sdb_close(fd);

    msg.data.id = ID_DONE;
    msg.data.size = 0;
    if(writex(s, &msg.data, sizeof(msg.data))) {
        return -1;
    }
    return 0;
}

static pid_t get_zone_init_pid(const char *name) {
    char filename[PATH_MAX];
    FILE *fp;
    pid_t ret = -1;

    snprintf(filename, sizeof(filename),
            "/sys/fs/cgroup/devices/lxc/%s/cgroup.procs", name);

    fp = fopen(filename, "r");

    if (fp != NULL) {
        if (fscanf(fp, "%d", &ret) < 0) {
            D("Failed to read %s\n", filename);
            ret = -2;
        }
        fclose(fp);
    } else {
        D("Unable to access %s\n", filename);
        ret = errno;
    }
    return ret;
}

void file_sync_service(int fd, void *cookie)
{
    syncmsg msg;
    char name[1025];
    unsigned namelen;
    fd_set set;
    struct timeval timeout;
    int rv;
    int s[2];
    char zone_path[1025] = {0, };
    char name_vsm[1025] = {0, };

    if(sdb_socketpair(s)) {
        D("cannot create service socket pair\n");
        exit(-1);
    }
    char *buffer = malloc(SYNC_DATA_MAX);
    if(buffer == 0) {
        goto fail;
    }

    FD_ZERO(&set); /* clear the set */
    FD_SET(fd, &set); /* add our file descriptor to the set */

    timeout.tv_sec = SYNC_TIMEOUT;
    timeout.tv_usec = 0;

    pid_t pid = fork();

    if (pid == 0) {
        sdb_close(s[0]); //close the parent fd
        sync_read_label_notify(s[1]);
    } else if (pid > 0) {
        sdb_close(s[1]);

        if (hostshell_mode == 0) {
            FILE *fp;
            fp = popen("/usr/bin/vsm-foreground", "r");
            if (fp == NULL) {
                D("Failed to create pipe of vsm-foreground\n");
                goto fail;
            }
            fgets(name_vsm, 1025, fp);
            pclose(fp);

            //trim zone name
            namelen = strlen(name_vsm);
            while (name_vsm[--namelen] == '\n')
                ;
            name_vsm[namelen + 1] = '\0';
            snprintf(zone_path, 1025, "/proc/%d/root",
                    get_zone_init_pid(name_vsm));
            chroot(zone_path);
            chdir("/");
        }

        for(;;) {
            D("sync: waiting for command for %d sec\n", SYNC_TIMEOUT);

            rv = select(fd + 1, &set, NULL, NULL, &timeout);
            if (rv == -1) {
                D("sync file descriptor select failed\n");
            } else if (rv == 0) {
                D("sync file descriptor timeout: (took %d sec over)\n", SYNC_TIMEOUT);
                fail_message(fd, "sync timeout");
                goto fail;
            }

            if(readx(fd, &msg.req, sizeof(msg.req))) {
                fail_message(fd, "command read failure");
                break;
            }
            namelen = ltohl(msg.req.namelen);
            if(namelen > 1024) {
                fail_message(fd, "invalid namelen");
                break;
            }
            if(readx(fd, name, namelen)) {
                fail_message(fd, "filename read failure");
                break;
            }
            name[namelen] = 0;

            msg.req.namelen = 0;
            D("sync: '%s' '%s'\n", (char*) &msg.req, name);

            if (should_drop_privileges()) {
                set_developer_privileges();
            }

            switch(msg.req.id) {
            case ID_STAT:
                if(do_stat(fd, name)) goto fail;
                break;
            case ID_LIST:
                if(do_list(fd, name)) goto fail;
                break;
            case ID_SEND:
                if(do_send(fd, s[0], name, buffer)) goto fail;
                break;
            case ID_RECV:
                if(do_recv(fd, name, buffer)) goto fail;
                break;
            case ID_QUIT:
                goto fail;
            default:
                fail_message(fd, "unknown command");
                goto fail;
            }
        }
    }


fail:
    if(buffer != 0) {
        free(buffer);
    }
    D("sync: done\n");
    sync_send_label_notify(s[0], name, 0);
    sdb_close(s[0]);
    sdb_close(s[1]);
    sdb_close(fd);
}
