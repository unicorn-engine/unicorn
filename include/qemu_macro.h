/* By Dang Hoang Vu <dang.hvu -at- gmail.com>, 2015 */

#ifndef UC_QEMU_MACRO_H
#define UC_QEMU_MACRO_H

#define CPU_NEXT(cpu) QTAILQ_NEXT(cpu, node)
#define CPU_FOREACH(cpu) QTAILQ_FOREACH(cpu, &uc->cpus, node)
#define CPU_FOREACH_SAFE(cpu, next_cpu) \
    QTAILQ_FOREACH_SAFE(cpu, &cpu->uc->cpus, node, next_cpu)
#define first_cpu QTAILQ_FIRST(&uc->cpus)

#endif

