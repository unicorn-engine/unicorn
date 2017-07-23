#define __STDC_FORMAT_MACROS
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unicorn/unicorn.h>


uint64_t baseranges[] = {0,0,0,0};
int step =0;

uint64_t urnd(){
  uint64_t rnd = rand();
  rnd = rnd << 32;
  rnd += rand();
  return rnd;
}
uint64_t get_addr(){
  uint64_t base = ((uint64_t)urnd())%4;
  uint64_t addr= baseranges[base] + urnd()%(4096*10);
  return addr;
}

uint64_t get_aligned_addr(){
  uint64_t addr = get_addr();
  return addr - (addr % 4096);
}

uint64_t get_len(){
  uint64_t len = (urnd() % (4096*5))+1;
  return len;
}

uint64_t get_aligned_len(){
  uint64_t len = get_len();
  len = len - (len %4096);
  len = ((len == 0) ? 4096 : len);
  return len;
}

void perform_map_step(uc_engine *uc){
    uint64_t addr = get_aligned_addr();
    uint64_t len = get_aligned_len();
    printf("map(uc,0x%"PRIx64",0x%"PRIx64"); //%d\n", addr, len, step);
    uc_mem_map(uc, addr, len, UC_PROT_READ | UC_PROT_WRITE);
}

void perform_unmap_step(uc_engine *uc){
    uint64_t addr = get_aligned_addr();
    uint64_t len = get_aligned_len();
    printf("unmap(uc,0x%"PRIx64",0x%"PRIx64"); //%d\n", addr, len, step);
    uc_mem_unmap(uc, addr, len);
}

void perform_write_step(uc_engine *uc){
    char buff[4096*4];
    memset((void *)buff, 0, 4096*4);
    uint64_t addr = get_addr();
    uint64_t len = get_len()%(4096*3);
    printf("write(uc,0x%"PRIx64",0x%"PRIx64"); //%d\n", addr, len, step);
    uc_mem_write(uc, addr, buff, len);
}

void perform_read_step(uc_engine *uc){
    char buff[4096*4];
    uint64_t addr = get_addr();
    uint64_t len = get_len()%(4096*4);
    printf("read(uc,0x%"PRIx64",0x%"PRIx64"); //%d\n", addr, len, step);
    uc_mem_read(uc, addr, buff, len);
}

void perform_fuzz_step(uc_engine *uc){
  switch( ((uint32_t)rand())%4 ){
    case 0: perform_map_step(uc); break;
    case 1: perform_unmap_step(uc); break;
    case 2: perform_read_step(uc); break;
    case 3: perform_write_step(uc); break;
  }
}

int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
    if(argc<2){
      printf("usage: mem_fuzz $seed\n");
      return 1;
    }
    int seed = atoi(argv[1]); 
    int i = 0;

    //don't really care about quality of randomness
    srand(seed);
    printf("running with seed %d\n",seed);

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return 1;
    } 

    for(i = 0; i < 2048; i++){
      step++;
      perform_fuzz_step(uc);
    }
    // fill in sections that shouldn't get touched

    if (uc_close(uc) != UC_ERR_OK) {
        printf("Failed on uc_close\n");
        return 1;
    }

    return 0;
}
