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
#include "sysdeps.h"

#define TRACE_TAG  TRACE_SYNC
#include "sdb.h"
#include "file_sync_service.h"

#define SYNC_TIMEOUT 15

struct sync_permit_rule
{
    const char *name;
    const char *regx;
    int mode; // 0:push, 1: pull, 2: push&push
};

struct sync_permit_rule sdk_sync_permit_rule[] = {
//    /* 0 */ {"rds", "^((/opt/apps)|(/opt/usr/apps))/[a-zA-Z0-9]{10}/info/\\.sdk_delta\\.info$", 1},
    /* 1 */ {"unitest", "^((/opt/apps)|(/opt/usr/apps))/[a-zA-Z0-9]{10}/data/[a-zA-Z0-9_\\-]{1,50}\\.xml$", 1},
    /* 2 */ {"codecoverage", "^((/opt/apps)|(/opt/usr/apps))/[a-zA-Z0-9]{10}/data/+([a-zA-Z0-9_/\\.])*+[a-zA-Z0-9_\\-\\.]{1,50}\\.gcda$", 1},
    /* 3 */ {"da", "^(/tmp/da/)*+[a-zA-Z0-9_\\-\\.]{1,50}\\.png$", 1},
    /* end */ {NULL, NULL, 0}
};

/* The typical default value for the umask is S_IWGRP | S_IWOTH (octal 022).
 * Before use the DIR_PERMISSION, the process umask value should be set 0 using umask().
 */
#define DIR_PERMISSION 0777

static int mkdirs(char *name)
{
    int ret;
    char *x = name + 1;

    if(name[0] != '/') return -1;

    for(;;) {
        x = sdb_dirstart(x);
        if(x == 0) return 0;
        *x = 0;
        /* tizen specific */
        ret = sdb_mkdir(name, DIR_PERMISSION);

        if((ret < 0) && (errno != EEXIST)) {
            D("mkdir(\"%s\") -> %s\n", name, strerror(errno));
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
        D("failed to stat %s due to: %s\n", path, strerror(errno));
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

    len = strlen(path);
    memcpy(tmp, path, len);
    tmp[len] = '/';
    fname = tmp + len + 1;

    msg.dent.id = ID_DENT;

    d = opendir(path);
    if(d == NULL) {
        D("failed to open dir due to: %s\n", strerror(errno));
        goto done;
    }

    while((de = readdir(d))) {
        int len = strlen(de->d_name);

            /* not supposed to be possible, but
               if it does happen, let's not buffer overrun */
        if(len > 256) {
            continue;
        }

        strcpy(fname, de->d_name);
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
    return fail_message(s, strerror(errno));
}

static int handle_send_file(int s, char *path, mode_t mode, char *buffer)
{
    syncmsg msg;
    unsigned int timestamp = 0;
    int fd;

    fd = sdb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if(fd < 0 && errno == ENOENT) {
        mkdirs(path);
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
    return 0;

fail:
    if(fd >= 0)
        sdb_close(fd);
    sdb_unlink(path);
    return -1;
}

#ifdef HAVE_SYMLINKS
static int handle_send_link(int s, char *path, char *buffer)
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
        mkdirs(path);
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

static int do_send(int s, char *path, char *buffer)
{
    char *tmp;
    mode_t mode;
    int is_link, ret;

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
    }
    if(!tmp || errno) {
        mode = 0644; // set default permission value in most of unix system.
        is_link = 0;
    }

    // sdb does not allow to check that file exists or not. After deleting old file and creating new file again unconditionally.
    sdb_unlink(path);


#ifdef HAVE_SYMLINKS
    if(is_link)
        ret = handle_send_link(s, path, buffer);
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
        ret = handle_send_file(s, path, mode, buffer);
    }

    return ret;
}

static int do_recv(int s, const char *path, char *buffer)
{
    syncmsg msg;
    int fd, r;

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

static int verify_sync_rule(const char* path) {
    regex_t regex;
    int ret;
    char buf[PATH_MAX];
    int i=0;

    for (i=0; sdk_sync_permit_rule[i].regx != NULL; i++) {
        ret = regcomp(&regex, sdk_sync_permit_rule[i].regx, REG_EXTENDED);
        if(ret){
            return 0;
        }
        // execute regular expression
        ret = regexec(&regex, path, 0, NULL, 0);
        if(!ret){
            regfree(&regex);
            D("found matched rule(%s) from %s path\n", sdk_sync_permit_rule[i].name, path);
            return 1;
        } else if( ret == REG_NOMATCH ){
            // do nothin
        } else{
            regerror(ret, &regex, buf, sizeof(buf));
            D("regex match failed(%s): %s\n",sdk_sync_permit_rule[i].name, buf);
        }
    }
    regfree(&regex);
    return 0;
}

void file_sync_service(int fd, void *cookie)
{
    syncmsg msg;
    char name[1025];
    unsigned namelen;
    fd_set set;
    struct timeval timeout;
    int rv;
    char *buffer = malloc(SYNC_DATA_MAX);
    if(buffer == 0) goto fail;

    FD_ZERO(&set); /* clear the set */
    FD_SET(fd, &set); /* add our file descriptor to the set */

    timeout.tv_sec = SYNC_TIMEOUT;
    timeout.tv_usec = 0;

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

        if (should_drop_privileges() && !verify_sync_rule(name)) {
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
            if(do_send(fd, name, buffer)) goto fail;
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

fail:
    if(buffer != 0) free(buffer);
    D("sync: done\n");
    sdb_close(fd);
}
