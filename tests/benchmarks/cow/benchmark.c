#include <unicorn/unicorn.h>
#include <gsl/gsl_rstat.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct data {
    gsl_rstat_workspace *rstat_p;
    struct timespec start;
};


void update_stats(gsl_rstat_workspace *rstat_p, struct timespec *start, struct timespec *end)
{
    double dur = (end->tv_sec - start->tv_sec) * 1000.0;
    dur += (end->tv_nsec - start->tv_nsec) / 1000000.0;
    gsl_rstat_add(dur, rstat_p);
}

static uint64_t CODEADDR = 0x1000;
static uint64_t DATABASE = 0x40000000;
static uint64_t BLOCKSIZE = 0x10000;

/*static void callback_mem(uc_engine *uc, uc_mem_type type, uint64_t addr, uint32_t size, uint64_t value, void *data)
{
    printf("callback mem valid: 0x%lX, value: 0x%lX\n", addr, value);
}*/
static int callback_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t addr, uint32_t size, int64_t value, void *data)
{
    printf("callback mem prot: 0x%lX, type: %X\n", addr, type);
    return false;
}

static void callback_block(uc_engine *uc, uint64_t addr, uint32_t size, void *data)
{
    struct timespec now;
    struct data *d = data;
    size_t run;
    uint64_t rax = 512;
    uint64_t rbx = DATABASE;
    uint64_t rsi;
    long memblock;
    long offset;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now);
    if (d->rstat_p) {
        update_stats(d->rstat_p, &d->start, &now);
    } else {
        d->rstat_p = gsl_rstat_alloc();
    }
    run = gsl_rstat_n(d->rstat_p);
    if ((run >> 4) >= 20) {
        uc_emu_stop(uc);
        return;
    } else if (run > 0 && run % 16 == 0) {
        uc_snapshot(uc);
    }
/*    if (run > 0 && run % 16 == 0) {
        uc_emu_stop(uc);
        return;
    }*/
    rsi = random();
    memblock = random() & 15;
    offset = random() & (BLOCKSIZE - 1) & (~0xf);
//    memblock = 0;
//    offset = 0;
    if (memblock == 15 && (offset + 0x1000) > BLOCKSIZE) {
        offset -= 0x1000;
    }
    rbx += (memblock * BLOCKSIZE) + offset;
    printf("write at 0x%lX\n", rbx);
    printf("[%li] callback block: 0x%lX\n", run, addr);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &d->start);
}

static void prepare_mapping(uc_engine *uc)
{
    for (size_t i = 0; i < 16; i++) {
        printf("mem map: 0x%lX\n", DATABASE+i*BLOCKSIZE);
        uc_mem_map(uc, DATABASE+i*BLOCKSIZE, BLOCKSIZE, UC_PROT_READ|UC_PROT_WRITE);
    }
}

static void prepare_code(uc_engine *uc, const char *file, void **addr)
{
    uc_err err;
    int fd;
    fd = open(file, O_RDONLY, 0);
    if (fd == -1) {
        perror("open");
        exit(1);
    }
    *addr = mmap(*addr, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    err = uc_mem_map_ptr(uc, CODEADDR, 0x1000, UC_PROT_READ|UC_PROT_EXEC, *addr);
    close(fd);
    if (err != UC_ERR_OK) {
        printf("err: %s\n", uc_strerror(err));
        exit(1);
    }
    printf("mapped %s\n", file);
    return;
}

void print_stats(gsl_rstat_workspace *rstat_p)
{
    double mean, variance, largest, smallest, sd,
           rms, sd_mean, median, skew, kurtosis;
    size_t n;

    mean     = gsl_rstat_mean(rstat_p);
    variance = gsl_rstat_variance(rstat_p);
    largest  = gsl_rstat_max(rstat_p);
    smallest = gsl_rstat_min(rstat_p);
    median   = gsl_rstat_median(rstat_p);
    sd       = gsl_rstat_sd(rstat_p);
    sd_mean  = gsl_rstat_sd_mean(rstat_p);
    skew     = gsl_rstat_skew(rstat_p);
    rms      = gsl_rstat_rms(rstat_p);
    kurtosis = gsl_rstat_kurtosis(rstat_p);
    n        = gsl_rstat_n(rstat_p);

    printf ("The sample mean is %g\n", mean);
    printf ("The estimated variance is %g\n", variance);
    printf ("The largest value is %g\n", largest);
    printf ("The smallest value is %g\n", smallest);
    printf( "The median is %g\n", median);
    printf( "The standard deviation is %g\n", sd);
    printf( "The root mean square is %g\n", rms);
    printf( "The standard devation of the mean is %g\n", sd_mean);
    printf( "The skew is %g\n", skew);
    printf( "The kurtosis %g\n", kurtosis);
    printf( "There are %zu items in the accumulator\n", n);
}
int main(int argc, char *argv[])
{
    uc_engine *uc;
    uc_err err;
    uc_hook hook_block;
    uc_hook hook_mem;
    struct data d;
    uint64_t rax = 5;
    uint64_t rbx = DATABASE;
    void *bin_mmap = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: %s binary\n", argv[0]);
        return 1;
    }

    d.rstat_p = NULL;
    srandom(time(NULL));

    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    prepare_code(uc, argv[1], &bin_mmap);
    prepare_mapping(uc);
    err = uc_hook_add(uc, &hook_block, UC_HOOK_BLOCK, &callback_block, &d, CODEADDR, 0x1000);
    if (err != UC_ERR_OK) {
        return 1;
    }
    uc_hook_add(uc, &hook_mem, UC_HOOK_MEM_INVALID, &callback_mem_prot, NULL, CODEADDR, 0x1000);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
/*    err = uc_hook_add(uc, &hook_mem, UC_HOOK_MEM_VALID, &callback_mem, NULL, DATABASE, 16*BLOCKSIZE);
    if (err) {
        printf("err: %s\n", uc_strerror(err));
        return 1;
    }*/
    for (int i = 0; i < 1; i++) {
        err = uc_emu_start(uc, CODEADDR, -1, 0, 0);
        if (err) {
            printf("err: %s\n", uc_strerror(err));
            return 1;
        }
        uc_snapshot(uc);
    }
    print_stats(d.rstat_p);
    return 0;
}
