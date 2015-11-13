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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "sdb.h"


struct usb_handle
{
    int fd;
    sdb_cond_t notify;
    sdb_mutex_t lock;
};

<<<<<<< HEAD
=======
void usb_cleanup()
{
    // nothing to do here
}

>>>>>>> tizen_2.4
static void *usb_open_thread(void *x)
{
    struct usb_handle *usb = (struct usb_handle *)x;
    int fd;

    while (1) {
        // wait until the USB device needs opening
        sdb_mutex_lock(&usb->lock);
        while (usb->fd != -1)
            sdb_cond_wait(&usb->notify, &usb->lock);
        sdb_mutex_unlock(&usb->lock);

        D("[ usb_thread - opening device ]\n");
        do {
            /* XXX use inotify? */
            fd = unix_open(USB_NODE_FILE, O_RDWR); /* tizen-specific */
            if (fd < 0) {
                // to support older kernels
                //fd = unix_open("/dev/android", O_RDWR);
                D("[ opening %s device failed ]\n", USB_NODE_FILE);
            }
            if (fd < 0) {
                sdb_sleep_ms(1000);
            }
        } while (fd < 0);
        D("[ opening device succeeded ]\n");

        if (close_on_exec(fd) < 0) {
            D("[closing fd exec failed ]\n");
        }
        usb->fd = fd;

        D("[ usb_thread - registering device ]\n");
        register_usb_transport(usb, 0, 1);
    }

    // never gets here
    return 0;
}

<<<<<<< HEAD
// Public host/client interface

int linux_usb_write(usb_handle *h, const void *data, int len)
=======
int usb_write(usb_handle *h, const void *data, int len)
>>>>>>> tizen_2.4
{
    int n;

    D("about to write (fd=%d, len=%d)\n", h->fd, len);
    n = sdb_write(h->fd, data, len);
    if(n != len) {
<<<<<<< HEAD
        D("ERROR: fd = %d, n = %d, errno = %d (%s)\n",
            h->fd, n, errno, strerror(errno));
=======
        D("ERROR: fd = %d, n = %d, errno = %d\n",
            h->fd, n, errno);
>>>>>>> tizen_2.4
        return -1;
    }
    D("[ done fd=%d ]\n", h->fd);
    return 0;
}

<<<<<<< HEAD
int linux_usb_read(usb_handle *h, void *data, int len)
=======
int usb_read(usb_handle *h, void *data, unsigned len)
>>>>>>> tizen_2.4
{
    int n;

    D("about to read (fd=%d, len=%d)\n", h->fd, len);
    n = sdb_read(h->fd, data, len);
    if(n != len) {
<<<<<<< HEAD
        D("ERROR: fd = %d, n = %d, errno = %d (%s)\n",
            h->fd, n, errno, strerror(errno));
=======
        D("ERROR: fd = %d, n = %d, errno = %d\n",
            h->fd, n, errno);
>>>>>>> tizen_2.4
        return -1;
    }
    D("[ done fd=%d ]\n", h->fd);
    return 0;
}

<<<<<<< HEAD
void linux_usb_init()
=======
void usb_init()
>>>>>>> tizen_2.4
{
    usb_handle *h;
    sdb_thread_t tid;
//  int fd;

    h = calloc(1, sizeof(usb_handle));
<<<<<<< HEAD
=======
    if (h == NULL) {
        D("failed to allocate memory of usb_handle\n");
        return;
    }

>>>>>>> tizen_2.4
    h->fd = -1;
    sdb_cond_init(&h->notify, 0);
    sdb_mutex_init(&h->lock, 0);

    // Open the file /dev/android_sdb_enable to trigger 
    // the enabling of the sdb USB function in the kernel.
    // We never touch this file again - just leave it open
    // indefinitely so the kernel will know when we are running
    // and when we are not.
#if 0 /* tizen specific */
    fd = unix_open("/dev/android_sdb_enable", O_RDWR);
    if (fd < 0) {
       D("failed to open /dev/android_sdb_enable\n");
    } else {
        close_on_exec(fd);
    }
#endif
    D("[ usb_init - starting thread ]\n");
    if(sdb_thread_create(&tid, usb_open_thread, h)){
        fatal_errno("cannot create usb thread");
    }
}

<<<<<<< HEAD
void linux_usb_kick(usb_handle *h)
=======
void usb_kick(usb_handle *h)
>>>>>>> tizen_2.4
{
    D("usb_kick\n");
    sdb_mutex_lock(&h->lock);
    sdb_close(h->fd);
    h->fd = -1;

    // notify usb_open_thread that we are disconnected
    sdb_cond_signal(&h->notify);
    sdb_mutex_unlock(&h->lock);
}

<<<<<<< HEAD
int linux_usb_close(usb_handle *h)
=======
int usb_close(usb_handle *h)
>>>>>>> tizen_2.4
{
    // nothing to do here
    return 0;
}
<<<<<<< HEAD

void linux_usb_cleanup()
{
    // nothing to do here
}
=======
>>>>>>> tizen_2.4
