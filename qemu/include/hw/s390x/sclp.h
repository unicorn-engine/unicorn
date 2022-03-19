/*
 * SCLP Support
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Christian Borntraeger <borntraeger@de.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at your
 * option) any later version.  See the COPYING file in the top-level directory.
 *
 */

#ifndef HW_S390_SCLP_H
#define HW_S390_SCLP_H

//#include "hw/sysbus.h"
#include "target/s390x/cpu-qom.h"

#define SCLP_CMD_CODE_MASK                      0xffff00ff

/* SCLP command codes */
#define SCLP_CMDW_READ_SCP_INFO                 0x00020001
#define SCLP_CMDW_READ_SCP_INFO_FORCED          0x00120001
#define SCLP_READ_STORAGE_ELEMENT_INFO          0x00040001
#define SCLP_ATTACH_STORAGE_ELEMENT             0x00080001
#define SCLP_ASSIGN_STORAGE                     0x000D0001
#define SCLP_UNASSIGN_STORAGE                   0x000C0001
#define SCLP_CMD_READ_EVENT_DATA                0x00770005
#define SCLP_CMD_WRITE_EVENT_DATA               0x00760005
#define SCLP_CMD_WRITE_EVENT_MASK               0x00780005

/* SCLP Memory hotplug codes */
#define SCLP_FC_ASSIGN_ATTACH_READ_STOR         0xE00000000000ULL
#define SCLP_STARTING_SUBINCREMENT_ID           0x10001
#define SCLP_INCREMENT_UNIT                     0x10000
#define MAX_STORAGE_INCREMENTS                  1020

/* CPU hotplug SCLP codes */
#define SCLP_HAS_CPU_INFO                       0x0C00000000000000ULL
#define SCLP_CMDW_READ_CPU_INFO                 0x00010001
#define SCLP_CMDW_CONFIGURE_CPU                 0x00110001
#define SCLP_CMDW_DECONFIGURE_CPU               0x00100001

/* SCLP PCI codes */
#define SCLP_HAS_IOA_RECONFIG                   0x0000000040000000ULL
#define SCLP_CMDW_CONFIGURE_IOA                 0x001a0001
#define SCLP_CMDW_DECONFIGURE_IOA               0x001b0001
#define SCLP_RECONFIG_PCI_ATYPE                 2

/* SCLP response codes */
#define SCLP_RC_NORMAL_READ_COMPLETION          0x0010
#define SCLP_RC_NORMAL_COMPLETION               0x0020
#define SCLP_RC_SCCB_BOUNDARY_VIOLATION         0x0100
#define SCLP_RC_NO_ACTION_REQUIRED              0x0120
#define SCLP_RC_INVALID_SCLP_COMMAND            0x01f0
#define SCLP_RC_CONTAINED_EQUIPMENT_CHECK       0x0340
#define SCLP_RC_INSUFFICIENT_SCCB_LENGTH        0x0300
#define SCLP_RC_STANDBY_READ_COMPLETION         0x0410
#define SCLP_RC_ADAPTER_IN_RESERVED_STATE       0x05f0
#define SCLP_RC_ADAPTER_TYPE_NOT_RECOGNIZED     0x06f0
#define SCLP_RC_ADAPTER_ID_NOT_RECOGNIZED       0x09f0
#define SCLP_RC_INVALID_FUNCTION                0x40f0
#define SCLP_RC_NO_EVENT_BUFFERS_STORED         0x60f0
#define SCLP_RC_INVALID_SELECTION_MASK          0x70f0
#define SCLP_RC_INCONSISTENT_LENGTHS            0x72f0
#define SCLP_RC_EVENT_BUFFER_SYNTAX_ERROR       0x73f0
#define SCLP_RC_INVALID_MASK_LENGTH             0x74f0


/* Service Call Control Block (SCCB) and its elements */

#define SCCB_SIZE 4096

#define SCLP_VARIABLE_LENGTH_RESPONSE           0x80
#define SCLP_EVENT_BUFFER_ACCEPTED              0x80

#define SCLP_FC_NORMAL_WRITE                    0

/*
 * Normally packed structures are not the right thing to do, since all code
 * must take care of endianness. We cannot use ldl_phys and friends for two
 * reasons, though:
 * - some of the embedded structures below the SCCB can appear multiple times
 *   at different locations, so there is no fixed offset
 * - we work on a private copy of the SCCB, since there are several length
 *   fields, that would cause a security nightmare if we allow the guest to
 *   alter the structure while we parse it. We cannot use ldl_p and friends
 *   either without doing pointer arithmetics
 * So we have to double check that all users of sclp data structures use the
 * right endianness wrappers.
 */
QEMU_PACK(typedef struct SCCBHeader {
    uint16_t length;
    uint8_t function_code;
    uint8_t control_mask[3];
    uint16_t response_code;
}) SCCBHeader;

#define SCCB_DATA_LEN (SCCB_SIZE - sizeof(SCCBHeader))
#define SCCB_CPU_FEATURE_LEN 6

/* CPU information */
QEMU_PACK(typedef struct CPUEntry {
    uint8_t address;
    uint8_t reserved0;
    uint8_t features[SCCB_CPU_FEATURE_LEN];
    uint8_t reserved2[6];
    uint8_t type;
    uint8_t reserved1;
}) CPUEntry;

QEMU_PACK(typedef struct ReadInfo {
    SCCBHeader h;
    uint16_t rnmax;
    uint8_t rnsize;
    uint8_t  _reserved1[16 - 11];       /* 11-15 */
    uint16_t entries_cpu;               /* 16-17 */
    uint16_t offset_cpu;                /* 18-19 */
    uint8_t  _reserved2[24 - 20];       /* 20-23 */
    uint8_t  loadparm[8];               /* 24-31 */
    uint8_t  _reserved3[48 - 32];       /* 32-47 */
    uint64_t facilities;                /* 48-55 */
    uint8_t  _reserved0[76 - 56];       /* 56-75 */
    uint32_t ibc_val;
    uint8_t  conf_char[99 - 80];        /* 80-98 */
    uint8_t mha_pow;
    uint32_t rnsize2;
    uint64_t rnmax2;
    uint8_t  _reserved6[116 - 112];     /* 112-115 */
    uint8_t  conf_char_ext[120 - 116];   /* 116-119 */
    uint16_t highest_cpu;
    uint8_t  _reserved5[124 - 122];     /* 122-123 */
    uint32_t hmfai;
    struct CPUEntry entries[];
}) ReadInfo;

QEMU_PACK(typedef struct ReadCpuInfo {
    SCCBHeader h;
    uint16_t nr_configured;         /* 8-9 */
    uint16_t offset_configured;     /* 10-11 */
    uint16_t nr_standby;            /* 12-13 */
    uint16_t offset_standby;        /* 14-15 */
    uint8_t reserved0[24-16];       /* 16-23 */
    struct CPUEntry entries[];
}) ReadCpuInfo;

QEMU_PACK(typedef struct ReadStorageElementInfo {
    SCCBHeader h;
    uint16_t max_id;
    uint16_t assigned;
    uint16_t standby;
    uint8_t _reserved0[16 - 14]; /* 14-15 */
    uint32_t entries[];
}) ReadStorageElementInfo;

QEMU_PACK(typedef struct AttachStorageElement {
    SCCBHeader h;
    uint8_t _reserved0[10 - 8];  /* 8-9 */
    uint16_t assigned;
    uint8_t _reserved1[16 - 12]; /* 12-15 */
    uint32_t entries[];
}) AttachStorageElement;

QEMU_PACK(typedef struct AssignStorage {
    SCCBHeader h;
    uint16_t rn;
}) AssignStorage;

QEMU_PACK(typedef struct IoaCfgSccb {
    SCCBHeader header;
    uint8_t atype;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t aid;
}) IoaCfgSccb;

QEMU_PACK(typedef struct SCCB {
    SCCBHeader h;
    char data[SCCB_DATA_LEN];
}) SCCB;

#define TYPE_SCLP "sclp"
#define SCLP(obj) OBJECT_CHECK(SCLPDevice, (obj), TYPE_SCLP)
#define SCLP_CLASS(oc) OBJECT_CLASS_CHECK(SCLPDeviceClass, (oc), TYPE_SCLP)
#define SCLP_GET_CLASS(obj) OBJECT_GET_CLASS(SCLPDeviceClass, (obj), TYPE_SCLP)

typedef struct SCLPEventFacility SCLPEventFacility;

typedef struct SCLPDevice {
    /* private */
    CPUState parent_obj;
    SCLPEventFacility *event_facility;
    int increment_size;

    /* public */
} SCLPDevice;

typedef struct SCLPDeviceClass {
    /* private */
    DeviceClass parent_class;
    void (*read_SCP_info)(SCLPDevice *sclp, SCCB *sccb);
    void (*read_cpu_info)(SCLPDevice *sclp, SCCB *sccb);

    /* public */
    void (*execute)(SCLPDevice *sclp, SCCB *sccb, uint32_t code);
    void (*service_interrupt)(SCLPDevice *sclp, uint32_t sccb);
} SCLPDeviceClass;

static inline int sccb_data_len(SCCB *sccb)
{
    return be16_to_cpu(sccb->h.length) - sizeof(sccb->h);
}


void s390_sclp_init(void);
void sclp_service_interrupt(uint32_t sccb);
void raise_irq_cpu_hotplug(void);
int sclp_service_call(CPUS390XState *env, uint64_t sccb, uint32_t code);

#endif
