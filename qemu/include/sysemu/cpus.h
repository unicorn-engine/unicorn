#ifndef QEMU_CPUS_H
#define QEMU_CPUS_H

struct uc_struct;

/* cpus.c */
int resume_all_vcpus(struct uc_struct*);
void cpu_stop_current(struct uc_struct*);

void cpu_synchronize_all_states(void);
void cpu_synchronize_all_post_reset(void);
void cpu_synchronize_all_post_init(void);

#ifndef CONFIG_USER_ONLY
/* vl.c */
extern int smp_cores;
extern int smp_threads;
#else
/* *-user doesn't have configurable SMP topology */
#define smp_cores   1
#define smp_threads 1
#endif

#endif
