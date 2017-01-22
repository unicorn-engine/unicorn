#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>

static int count = 1;

bool cb_hookunmapped(uc_engine *uc, uc_mem_type type, uint64_t address, uint32_t size, int64_t value, void *user_data) {
   uint32_t pc = 0;
   uc_reg_read(uc, UC_X86_REG_EIP, &pc);
   fprintf(stderr, "mem unmapped: 0x%x type: %x address: 0x%"PRIx64" length: %x value: 0x%"PRIx64"\n", 
           pc, type, address, size, value);

   uc_err err = UC_ERR_OK;
   err = uc_emu_stop(uc);
   if (err != UC_ERR_OK) {
       fprintf(stderr, "stop not ok");
       exit(0);
   }
   return true;
}

// move esi, dword ptr [ecx + eax + 0x28]
// add esi, eax
// lea eax, dword ptr [ebp - 4]
// push eax
// push 0x40
// push 0x10
// push esi
// call some address
#define CODE "\x8B\x74\x01\x28" \
             "\x0C\xF0" \
             "\x8D\x45\xFC" \
             "\x50" \
             "\x6A\x40" \
             "\x6A\x10" \
             "\x56" \
             "\xFF\x15\x20\x20\x00\x10"

int main() {
   uc_engine *uc;

   uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_open\n", count++);

   err = uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_mem_map: code\n", count++);

   uint8_t code[0x1000];
   memset(code, 0x0, sizeof(code));
   memcpy(code, CODE, sizeof(CODE));

   err = uc_mem_write(uc, 0x1000, code, sizeof(code));
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_mem_write: code\n", count++);

   uint32_t eip = 0x1000;
   err = uc_reg_write(uc, UC_X86_REG_EIP, &eip);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_reg_write: eip\n", count++);

   err = uc_mem_map(uc, 0x4000, 0x4000, UC_PROT_ALL);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_mem_map: stack\n", count++);

   uint8_t stack[0x4000];
   memset(stack, 0x0, sizeof(stack));

   err = uc_mem_write(uc, 0x4000, code, sizeof(code));
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_mem_write: stack\n", count++);

   uint32_t esp = 0x6000;
   err = uc_reg_write(uc, UC_X86_REG_ESP, &esp);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_reg_write: esp\n", count++);

   uint32_t ebp = 0x6000;
   err = uc_reg_write(uc, UC_X86_REG_EBP, &ebp);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_reg_write: ebp\n", count++);

   uc_hook h1;

   err = uc_hook_add(uc, &h1, UC_HOOK_MEM_UNMAPPED, cb_hookunmapped, NULL, 1, 0);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_hook_add\n", count++);

   // this should execute only a single instruction at 0x1000, because
   // that instruction accesses invalid memory.
   err = uc_emu_start(uc, 0x1000, 0x100F, 0, 0);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_emu_start\n", count++);

   // yes, not necessary, but to demonstrate the UC API is working as expected
   eip = 0x1004;
   err = uc_reg_write(uc, UC_X86_REG_EIP, &eip);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_reg_write: eip\n", count++);

   // this should execute the remaining instructions up to (but not includign) 0x100F.
   // currently, it returns an error about an unmapped read.
   // seems that this error should have been returned in the previous call
   //  to emu_start.
   err = uc_emu_start(uc, 0x1004, 0x100F, 0, 0);
   if (err != UC_ERR_OK) {
      fprintf(stderr, "not ok %d - %s\n", count++, uc_strerror(err));
      exit(0);
   }
   fprintf(stderr, "ok %d - uc_emu_start\n", count++);

   fprintf(stderr, "ok %d - Done", count++);

   return 0;
}
