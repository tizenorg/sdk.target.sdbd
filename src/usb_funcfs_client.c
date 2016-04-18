/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd
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
#include <sys/poll.h>
#include <dirent.h>
#include <errno.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "sdb.h"

#define MAX_PACKET_SIZE_FS	64
#define MAX_PACKET_SIZE_HS	512

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

static const char ep0_path[] = USB_FUNCFS_SDB_PATH"/ep0";
static const char ep1_path[] = USB_FUNCFS_SDB_PATH"/ep1";
static const char ep2_path[] = USB_FUNCFS_SDB_PATH"/ep2";

static const struct {
    struct usb_functionfs_descs_head header;
    struct {
        struct usb_interface_descriptor intf;
        struct usb_endpoint_descriptor_no_audio source;
        struct usb_endpoint_descriptor_no_audio sink;
    } __attribute__((packed)) fs_descs, hs_descs;
} __attribute__((packed)) descriptors = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC),
        .length = cpu_to_le32(sizeof(descriptors)),
        .fs_count = 3,
        .hs_count = 3,
    },
    .fs_descs = {
        .intf = {
            .bLength = sizeof(descriptors.fs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = SDB_CLASS,
            .bInterfaceSubClass = SDB_SUBCLASS,
            .bInterfaceProtocol = SDB_PROTOCOL,
            .iInterface = 1, /* first string from the provided table */
        },
        .source = {
            .bLength = sizeof(descriptors.fs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
        .sink = {
          .bLength = sizeof(descriptors.fs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
    },
    .hs_descs = {
        .intf = {
            .bLength = sizeof(descriptors.hs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = SDB_CLASS,
            .bInterfaceSubClass = SDB_SUBCLASS,
            .bInterfaceProtocol = SDB_PROTOCOL,
            .iInterface = 1, /* first string from the provided table */
        },
        .source = {
            .bLength = sizeof(descriptors.hs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
        .sink = {
            .bLength = sizeof(descriptors.hs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
    },
};

#define STR_INTERFACE "SDB Interface"

static const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_STRINGS_MAGIC),
        .length = cpu_to_le32(sizeof(strings)),
        .str_count = cpu_to_le32(1),
        .lang_count = cpu_to_le32(1),
    },
    .lang0 = {
        cpu_to_le16(0x0409), /* en-us */
        STR_INTERFACE,
    },
};


/* A local struct to store state of application */
struct usb_handle
{
    const char *EP0_NAME;
    const char *EP_IN_NAME;
    const char *EP_OUT_NAME;
    int control;
    int bulk_out; /* "out" from the host's perspective => source for sdbd */
    int bulk_in;  /* "in" from the host's perspective => sink for sdbd */
    sdb_cond_t notify;
    sdb_mutex_t lock;
    sdb_cond_t control_notify;
    sdb_mutex_t control_lock;
    sdb_cond_t kick_notify;
    sdb_mutex_t kick_lock;
    int ffs_enabled;
    int needs_kick;
};


/*
 * Initializes FunctionFS by writing descriptors and strings
 * to control endpoint (EP0)
 */
static void init_functionfs(struct usb_handle *h)
{
    ssize_t ret;

    sdb_mutex_lock(&h->control_lock);

    /* open control endpoint */
    D("OPENING %s\n", h->EP0_NAME);
    h->control = sdb_open(h->EP0_NAME, O_RDWR);
    if (h->control < 0) {
        D("[ %s: cannot open control endpoint ]\n", h->EP0_NAME);
        h->control = -errno;
        sdb_mutex_unlock(&h->control_lock);
        goto error;
    }

    /* write descriptors to control endpoint */
    D("[ %s: writing descriptors ]\n", h->EP0_NAME);
    ret = sdb_write(h->control, &descriptors, sizeof(descriptors));
    if (ret < 0) {
        D("[ %s: cannot write descriptors ]\n", h->EP0_NAME);
        sdb_mutex_unlock(&h->control_lock);
        goto error;
    }

    /* write strings to control endpoint */
    D("[ %s: writing strings ]\n", h->EP0_NAME);
    ret = sdb_write(h->control, &strings, sizeof(strings));
    if(ret < 0) {
        D("[ %s: cannot write strings ]\n", h->EP0_NAME);
        sdb_mutex_unlock(&h->control_lock);
        goto error;
    }

    sdb_cond_signal(&h->control_notify);
    sdb_mutex_unlock(&h->control_lock);

    /* once configuration is passed to FunctionFS, io endpoints can be opened */

    /* open output endpoint */
    D("[ %s: opening ]\n", h->EP_OUT_NAME);
    if ((h->bulk_out = sdb_open(h->EP_OUT_NAME, O_RDWR)) < 0) {
        D("[ %s: cannot open bulk-out endpoint ]\n", h->EP_OUT_NAME);
        h->bulk_out = -errno;
        goto error;
    }

    /* open input endpoint */
    D("[ %s: opening ]\n", h->EP_IN_NAME);
    if ((h->bulk_in = sdb_open(h->EP_IN_NAME, O_RDWR)) < 0) {
        D("[ %s: cannot open bulk-in endpoint ]\n", h->EP_IN_NAME);
        h->bulk_in = -errno;
        goto error;
    }

    return;

error:
    if (h->bulk_in > 0) {
        sdb_close(h->bulk_in);
        h->bulk_in = -1;
    }
    if (h->bulk_out > 0) {
        sdb_close(h->bulk_out);
        h->bulk_out = -1;
    }
    if (h->control > 0) {
        sdb_close(h->control);
        h->control = -1;
    }
}

static void *usb_open_thread(void *x)
{
    struct usb_handle *usb = (struct usb_handle *)x;

    init_functionfs(usb);
    if (usb->control < 0 || usb->bulk_in < 0 || usb->bulk_out < 0) {
        D("[ opening device failed ]\n");
        return (void *)-1;
    }

    D("[ opening device succeeded ]\n");

    /* wait until the USB device becomes operational */
    sdb_mutex_lock(&usb->lock);
    while (usb->ffs_enabled == 0)
        sdb_cond_wait(&usb->notify, &usb->lock);
    sdb_mutex_unlock(&usb->lock);

    D("[ usb_thread - registering device ]\n");
    register_usb_transport(usb, NULL, 1);	/* writable transport */

    while (1) {
        /* wait until the USB device needs reset */
        D("%s: WAIT UNTIL NEEDS RESET\n", __func__);
        sdb_mutex_lock(&usb->kick_lock);
        while (usb->needs_kick != 1)
            sdb_cond_wait(&usb->kick_notify, &usb->kick_lock);
        usb->needs_kick = 0;
        sdb_mutex_unlock(&usb->kick_lock);

        /* wait until the USB device becomes operational */
        D("%s: WAIT UNTIL OPERATIONAL\n", __func__);
        sdb_mutex_lock(&usb->lock);
        while (usb->ffs_enabled == 0)
            sdb_cond_wait(&usb->notify, &usb->lock);
        sdb_mutex_unlock(&usb->lock);

        D("[ usb_thread - registering device ]\n");
        register_usb_transport(usb, NULL, 1);	/* writable transport */
    }

    /* never gets here */
    return 0;
}


/*
 * Reads and dispatches control messages
 *
 * @returns cumulative size of read messages or negative error number
 */
static int read_control(struct usb_handle *usb)
{
    static const char *const names[] = {
        [FUNCTIONFS_BIND] = "BIND",
        [FUNCTIONFS_UNBIND] = "UNBIND",
        [FUNCTIONFS_ENABLE] = "ENABLE",
        [FUNCTIONFS_DISABLE] = "DISABLE",
        [FUNCTIONFS_SETUP] = "SETUP",
        [FUNCTIONFS_SUSPEND] = "SUSPEND",
        [FUNCTIONFS_RESUME] = "RESUME",
    };
    const struct usb_functionfs_event read_event;
    int ret;

    /* Read events from control endpoint
       Fortunately, FunctionFS guarantees reading of full event (or nothing),
       so we're not bothered with ret < sizeof(read_event) */
    ret = sdb_read(usb->control, (void *)&read_event, sizeof(read_event));
    if (ret < 0) {
        /* EAGAIN support will be useful, when non-blocking ep0 reads
           are supported in FunctionFS */
        if (errno == EAGAIN) {
            sleep(1);
            return ret;
        }
        perror("ep0 read after poll");
        return ret;
    }

    /* dispatch read event */
	switch (read_event.type) {
		case FUNCTIONFS_RESUME:
		case FUNCTIONFS_ENABLE:
			D("FFSEvent %s\n", names[read_event.type]);
			sdb_mutex_lock(&usb->lock);
			usb->ffs_enabled = 1;
			sdb_cond_signal(&usb->notify);
			sdb_mutex_unlock(&usb->lock);
			break;

		case FUNCTIONFS_SUSPEND:
		case FUNCTIONFS_DISABLE:
			D("FFSEvent %s\n", names[read_event.type]);
			sdb_mutex_lock(&usb->lock);
			usb->ffs_enabled = 0;
			sdb_mutex_unlock(&usb->lock);
			break;

		case FUNCTIONFS_BIND:
		case FUNCTIONFS_UNBIND:
		case FUNCTIONFS_SETUP:
			D("FFSEvent %s\n", names[read_event.type]);
			break;

		default:
			D("FFSEvent event (type=%d) is unknown -- ignored\n", read_event.type);
			break;
	}

    return ret;
}


/*
 * Polls for control messages
 *
 * Calls read_control if control messages arrive
 */
static void *usb_read_control(void *x)
{
    struct usb_handle *usb = (struct usb_handle *)x;
    struct pollfd ep0_poll[1];
    int ret;

    sdb_mutex_lock(&usb->control_lock);
    while (usb->control == -1)
        sdb_cond_wait(&usb->control_notify, &usb->control_lock);
    sdb_mutex_unlock(&usb->control_lock);

    while (1) {
        ep0_poll[0].fd = usb->control;
        ep0_poll[0].events = POLLIN;

        /* In fact, polling ep0 is not yet supported in FunctionFS,
           but we want the code to be ready for it.
           The current approach makes no harm, because poll returns
           immediately and we end up waiting on read (in read_control()). */
        ret = poll(ep0_poll, 1, -1);
        if (ret < 0) {
            perror("poll on control endpoint");
            continue;
        }

        if (ep0_poll[0].revents & POLLIN) {
            ret = read_control(usb);
        }
    }

    return 0;
}


/*
 * Writes data to bulkin_fd
 *
 * Blocks until length data is written or error occurs.
 *
 * @returns amount of bytes written or -1 on failure (errno is set)
 */
static int bulk_write(int bulkin_fd, const void *buf, size_t length)
{
    size_t count = 0;
    int ret;

    do {
        ret = sdb_write(bulkin_fd, buf + count, length - count);
        if (ret < 0) {
            if (errno != EINTR)
                return ret;
            } else
                count += ret;
    } while (count < length);

    D("[ bulk_write done fd=%d ]\n", bulkin_fd);
    return count;
}


/*
 * Reads data from bulkout_fd
 *
 * Blocks until length data is read or error occurs.
 *
 * @returns amount of bytes read or -1 on failure (errno is set)
 */
static int bulk_read(int bulkout_fd, void *buf, size_t length)
{
    size_t count = 0;
    int ret;

    do {
        D("%d: before sdb_read...\n", getpid());
        ret = sdb_read(bulkout_fd, buf + count, length - count);
        D("%d: after sdb_read...\n", getpid());

        if (ret < 0) {
            if (errno != EINTR) {
                return ret;
            }
		} else {
            count += ret;
		}

    } while (count < length);

    D("[ bulk_read done fd=%d ]\n", bulkout_fd);
    return count;
}

/*
 * Checks if EP0 exists on filesystem
 */
static int ep0_exists()
{
	struct stat statb;
	return stat(ep0_path, &statb) == 0;
}


/*
 * Initializes struct usb_handle with paths to endpoints
 *
 * Fails, if EP0 does not exist on filesystem.
 *
 * @returns 0 on success or -ENODEV on failure
 */
static int autoconfig(struct usb_handle *h)
{
    if (!ep0_exists()) {
        return -ENODEV;
    }

	h->EP0_NAME = ep0_path;
	h->EP_OUT_NAME = ep1_path;
	h->EP_IN_NAME = ep2_path;
    return 0;
}


/*
 * Public host/client interface
 */


/*
 * Creates and starts USB threads
 */
void ffs_usb_init()
{
    usb_handle *h;
    sdb_thread_t tid;

    D("[ usb_init - using FunctionFS ]\n");

    h = calloc(1, sizeof(usb_handle));
    if (autoconfig(h) < 0) {
        perror("[ can't recognize usb FunctionFS bulk device ]\n");
        free(h);
        return;
    }

    h->control = h->bulk_out = h->bulk_in = -1;
    h->ffs_enabled = h->needs_kick = 0;

    sdb_cond_init(&h->notify, 0);
    sdb_mutex_init(&h->lock, 0);

    sdb_cond_init(&h->control_notify, 0);
    sdb_mutex_init(&h->control_lock, 0);

    sdb_cond_init(&h->kick_notify, 0);
    sdb_mutex_init(&h->kick_lock, 0);

    D("[ usb_init - starting thread ]\n");
    if(sdb_thread_create(&tid, usb_open_thread, h))
        fatal_errno("[ cannot create usb thread ]\n");

    if(sdb_thread_create(&tid, usb_read_control, h))
        fatal_errno("[ cannot create usb read control thread ]\n");
}


void ffs_usb_cleanup()
{
    /* nothing to do here */
}


/*
 * Writes data to bulk_in descriptor
 *
 * In fact, data is forwarded to bulk_write.
 *
 * @returns 0 on success and -1 on failure (errno is set)
 */
int ffs_usb_write(usb_handle *h, const void *data, int len)
{
    int n;

    D("about to write (fd=%d, len=%d)\n", h->bulk_in, len);
    n = bulk_write(h->bulk_in, data, len);
    if(n != len) {
        D("ERROR: fd = %d, n = %d, errno = %d\n",
            h->bulk_in, n, errno);
        return -1;
    }
    D("[ done fd=%d ]\n", h->bulk_in);
    return 0;
}


/*
 * Reads data from bulk_out descriptor
 *
 * In fact, reading task is forwarded to bulk_read.
 *
 * @returns 0 on success and -1 on failure (errno is set)
 */
int ffs_usb_read(usb_handle *h, void *data, size_t len)
{
    int n;

    D("%d: about to read (fd=%d, len=%d)\n", getpid(), h->bulk_out, len);
    n = bulk_read(h->bulk_out, data, len);
    if(n != len) {
        D("ERROR: fd = %d, n = %d, errno = %d\n",
            h->bulk_out, n, errno);
        return -1;
    }
    D("[ done fd=%d ]\n", h->bulk_out);
    return 0;
}


int ffs_usb_close(usb_handle *h)
{
    return 0;
}


void ffs_usb_kick(usb_handle *h)
{
    int err;

    err = ioctl(h->bulk_in, FUNCTIONFS_CLEAR_HALT);
    if (err < 0)
        perror("[ reset source fd ]\n");

    err = ioctl(h->bulk_out, FUNCTIONFS_CLEAR_HALT);
    if (err < 0)
        perror("reset sink fd");

    sdb_mutex_lock(&h->kick_lock);
    h->needs_kick = 1;

    /* notify usb_open_thread that we are disconnected */
    sdb_cond_signal(&h->kick_notify);
    sdb_mutex_unlock(&h->kick_lock);
}
