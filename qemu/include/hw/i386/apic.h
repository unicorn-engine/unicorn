#ifndef APIC_H
#define APIC_H

#include "qemu-common.h"

/* apic.c */
int apic_accept_pic_intr(DeviceState *s);
int apic_get_interrupt(DeviceState *s);
void cpu_set_apic_base(struct uc_struct *uc, DeviceState *s, uint64_t val);
uint64_t cpu_get_apic_base(struct uc_struct *uc, DeviceState *s);
void cpu_set_apic_tpr(struct uc_struct *uc, DeviceState *s, uint8_t val);
uint8_t cpu_get_apic_tpr(struct uc_struct *uc, DeviceState *s);
void apic_init_reset(struct uc_struct *uc, DeviceState *s);
void apic_sipi(DeviceState *s);
void apic_handle_tpr_access_report(DeviceState *d, target_ulong ip,
                                   TPRAccess access);
void apic_poll_irq(DeviceState *d);
void apic_designate_bsp(struct uc_struct *uc, DeviceState *d);

/* pc.c */
DeviceState *cpu_get_current_apic(struct uc_struct *uc);

/* cpu.c */
bool cpu_is_bsp(X86CPU *cpu);

void apic_register_types(struct uc_struct *uc);
void apic_common_register_types(struct uc_struct *uc);

#endif
