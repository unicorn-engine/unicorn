#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <unicorn/unicorn.h>

static count = 1;

// Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
// @address: address where the code is being executed
// @size: size of machine instruction being executed
// @user_data: user data passed to tracing APIs.
void cb_hookblock(uch handle, uint64_t address, uint32_t size, void *user_data) {
   fprintf(stderr, "# >>> Tracing basic block at 0x%llx, block size = 0x%x\n", address, size);
   if (address != 0x1000000 && address != 0x1000200) {
      fprintf(stderr, "not ok %d - address != 0x1000000 && address != 0x1000200\n", count++);
      _exit(1);
   }
   fprintf(stderr, "ok %d - address (0x%x) is start of basic block\n", count++, address);
   if (size != 0x200) {
      fprintf(stderr, "not ok %d - basic block size != 0x200\n", count++);
      _exit(1);
   }
   fprintf(stderr, "ok %d - basic block size is correct\n", count++);
}

int main() {
   uch u;

   fprintf(stderr, "# basic block callback test\n");
   fprintf(stderr, "# there are only two basic blocks 0x1000000-0x10001ff and 0x1000200-0x10003ff\n");
   
   uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &u);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_open\n", count++);

   err = uc_mem_map(u, 0x1000000, 4096);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_mem_map\n", count++);

   uint8_t code[1024];
   //build a program that consists of 1019 nops followed by a jump -512
   //this program contains exactly 2 basic blocks, a block of 512 nops, followed
   //by a loop body containing 507 nops and jump to the top of the loop
   //the first basic block begins at address 0x1000000, and the second
   //basic block begins at address 0x1000200
   memset(code, 0x90, sizeof(code));
   memcpy(code + 1024 - 5, "\xe9\x00\xfe\xff\xff", 5);

   err = uc_mem_write(u, 0x1000000, code, sizeof(code));
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_mem_write\n", count++);
   
   uch h1, h2;

   err = uc_hook_add(u, &h1, UC_HOOK_BLOCK, cb_hookblock, NULL, (uint64_t)1, (uint64_t)0);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_hook_add\n", count++);

   err = uc_emu_start(u, 0x1000000, 0x1000000 + sizeof(code), 0, 1030);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_emu_start\n", count++);

   fprintf(stderr, "ok %d - Done", count++);
}
