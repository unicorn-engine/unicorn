#ifndef SYSEMU_H
#define SYSEMU_H

struct uc_struct;

void qemu_system_reset_request(struct uc_struct*);
void qemu_system_shutdown_request(struct uc_struct*);

#endif
