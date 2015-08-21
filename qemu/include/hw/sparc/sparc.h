#ifndef HW_SPARC_H
#define HW_SPARC_H

void sparc_cpu_register_types(void *opaque);
void leon3_machine_init(struct uc_struct *uc);
void sun4u_machine_init(struct uc_struct *uc);

#endif
