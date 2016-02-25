#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#define   TRACE_TAG  TRACE_USB

#define MAX_PACKET_SIZE_FS	64
#define MAX_PACKET_SIZE_HS	512

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

extern struct sdb_usb_descs {
    struct usb_functionfs_descs_head header;
    struct {
        struct usb_interface_descriptor intf;
        struct usb_endpoint_descriptor_no_audio source;
        struct usb_endpoint_descriptor_no_audio sink;
    } __attribute__((packed)) fs_descs, hs_descs;
} __attribute__((packed)) descriptors;

#define STR_INTERFACE "SDB Interface"

extern struct sdb_usb_strings {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings;
