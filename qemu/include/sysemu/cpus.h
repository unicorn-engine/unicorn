#ifndef QEMU_CPUS_H
#define QEMU_CPUS_H

struct uc_struct;

/* cpus.c */
int resume_all_vcpus(struct uc_struct*);
void cpu_stop_current(struct uc_struct*);

/* vl.c */
extern int smp_cores;
extern int smp_threads;

#endif
