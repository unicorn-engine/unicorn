#include <unicorn/unicorn.h>

#define HARDWARE_ARCHITECTURE UC_ARCH_SPARC
#define HARDWARE_MODE UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN

#define MEMORY_STARTING_ADDRESS 0x1000000
#define MEMORY_SIZE 2 * 1024 * 1024
#define MEMORY_PERMISSIONS UC_PROT_ALL

#define BINARY_CODE "\x02\xbc\x00\x00"

int main(int argc, char **argv, char **envp) {
  uc_engine *uc;
  if (uc_open(HARDWARE_ARCHITECTURE, HARDWARE_MODE, &uc)) {
    printf("uc_open(…) failed\n");
    return 1;
  }
  uc_mem_map(uc, MEMORY_STARTING_ADDRESS, MEMORY_SIZE, MEMORY_PERMISSIONS);
  if (uc_mem_write(uc, MEMORY_STARTING_ADDRESS, BINARY_CODE, sizeof(BINARY_CODE) - 1)) {
    printf("uc_mem_write(…) failed\n");
    return 1;
  }
  printf("uc_emu_start(…)\n");
  uc_emu_start(uc, MEMORY_STARTING_ADDRESS, MEMORY_STARTING_ADDRESS + sizeof(BINARY_CODE) - 1, 0, 20);
  printf("done\n");
  return 0;
}
