#ifndef QEMU_CPUS_H
#define QEMU_CPUS_H

#include "qemu/timer.h"

/* cpus.c */
bool qemu_in_vcpu_thread(void);
void qemu_init_cpu_loop(void);
void resume_all_vcpus(struct uc_struct* uc);
void cpu_stop_current(struct uc_struct* uc);
void cpu_ticks_init(void);

/* Unblock cpu */
void qemu_cpu_kick_self(void);

void cpu_synchronize_all_states(void);
void cpu_synchronize_all_post_reset(void);
void cpu_synchronize_all_post_init(void);
void cpu_synchronize_all_pre_loadvm(void);

void qtest_clock_warp(int64_t dest);

void list_cpus(const char *optarg);

#endif
