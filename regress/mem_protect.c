#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <unicorn/unicorn.h>

unsigned char PROGRAM[] =
   "\xc7\x05\x00\x00\x40\x00\x41\x41\x41\x41\x90\xc7\x05\x00\x00\x40"
   "\x00\x42\x42\x42\x42\x90\xc7\x05\x01\x00\x40\x00\x43\x43\x43\x43"
   "\x90\xc7\x05\x01\x00\x40\x00\x44\x44\x44\x44\x90\x66\xc7\x05\x02"
   "\x00\x40\x00\x45\x45\x90\x66\xc7\x05\x02\x00\x40\x00\x46\x46\x90"
   "\x66\xc7\x05\x01\x00\x40\x00\x47\x47\x90\x66\xc7\x05\x01\x00\x40"
   "\x00\x48\x48\x90\xc6\x05\x03\x00\x40\x00\x49\x90\xc6\x05\x03\x00"
   "\x40\x00\x4a\x90\xf4";
// total size: 101 bytes

/*
bits 32

; assumes code section at 0x100000
; assumes data section at 0x400000, initially rw?

; with installed hooks toggles UC_PROT_WRITE on each nop

   mov dword [0x400000], 0x41414141  ; aligned
   nop
   mov dword [0x400000], 0x42424242  ; aligned
   nop
   mov dword [0x400001], 0x43434343  ; unaligned
   nop
   mov dword [0x400001], 0x44444444  ; unaligned
   nop
   mov word [0x400002], 0x4545  ; aligned
   nop
   mov word [0x400002], 0x4646  ; aligned
   nop
   mov word [0x400001], 0x4747  ; unaligned
   nop
   mov word [0x400001], 0x4848  ; unaligned
   nop
   mov byte [0x400003], 0x49  ; unaligned
   nop
   mov byte [0x400003], 0x4A  ; unaligned
   nop
   hlt    ; tell hook function we are done
*/

int test_num  = 0;
const uint8_t *tests[] = {
   (uint8_t*)"\x41\x41\x41\x41\x00",
   (uint8_t*)"\x42\x42\x42\x42\x00",
   (uint8_t*)"\x42\x43\x43\x43\x43",
   (uint8_t*)"\x42\x44\x44\x44\x44",
   (uint8_t*)"\x42\x44\x45\x45\x44",
   (uint8_t*)"\x42\x44\x46\x46\x44",
   (uint8_t*)"\x42\x47\x47\x46\x44",
   (uint8_t*)"\x42\x48\x48\x46\x44",
   (uint8_t*)"\x42\x48\x48\x49\x44",
   (uint8_t*)"\x42\x48\x48\x4A\x44",
};

static int log_num = 1;

#define CODE_SECTION 0x100000
#define CODE_SIZE 0x1000

#define DATA_SECTION 0x400000
#define DATA_SIZE 0x1000

static uint32_t current_perms = UC_PROT_READ | UC_PROT_WRITE;

static void hexdump(const char *prefix, const uint8_t *bytes, uint32_t len) {
   uint32_t i;
   printf("%s", prefix);
   for (i = 0; i < len; i++) {
      printf("%02hhx", bytes[i]);
   }
   printf("\n");
}

// callback for tracing instruction
static void hook_code(uch handle, uint64_t addr, uint32_t size, void *user_data) {
   uint8_t opcode;
   uint8_t bytes[5];
   if (uc_mem_read(handle, addr, &opcode, 1) != UC_ERR_OK) {
      printf("not ok %d - uc_mem_read fail during hook_code callback, addr: 0x%" PRIu64 "\n", log_num++, addr);
      _exit(1);
   }
   printf("ok %d - uc_mem_read for opcode\n", log_num++);
   switch (opcode) {
      case 0x90:  //nop
         if (uc_mem_read(handle, DATA_SECTION, bytes, sizeof(bytes)) != UC_ERR_OK) {
            printf("not ok %d - uc_mem_read fail for address: 0x%" PRIu64 "\n", log_num++, addr);
            _exit(1);
         }
         printf("ok %d - uc_mem_read for test %d\n", log_num++, test_num);

         if (memcmp(bytes, tests[test_num], sizeof(bytes)) == 0) {
            printf("ok %d - passed test %d\n", log_num++, test_num);
         }
         else {
            printf("not ok %d - failed test %d\n", log_num++, test_num);
            hexdump("# Expected: ", tests[test_num], sizeof(bytes));
            hexdump("# Received: ", bytes, sizeof(bytes));
         }         
         test_num++;
         current_perms ^= UC_PROT_WRITE;
         if (uc_mem_protect(handle, DATA_SECTION, DATA_SIZE, current_perms) != UC_ERR_OK) {
            printf("not ok %d - uc_mem_protect fail during hook_code callback, addr: 0x%" PRIu64 "\n", log_num++, addr);
            _exit(1);
         }
         else {
            printf("ok %d - uc_mem_protect UC_PROT_WRITE toggled\n", log_num++);
         }
         break;
      case 0xf4:  //hlt
         if (uc_emu_stop(handle) != UC_ERR_OK) {
            printf("not ok %d - uc_emu_stop fail during hook_code callback, addr: 0x%" PRIu64 "\n", log_num++, addr);
            _exit(1);
         }
         else {
            printf("ok %d - hlt encountered, uc_emu_stop called\n", log_num++);
         }
         break;
      default:  //all others
         break;
   }
}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uch handle, uc_mem_type type,
        uint64_t addr, int size, int64_t value, void *user_data) {
   uint8_t bytes[5];   
   switch(type) {
      default:
         printf("not ok %d - UC_HOOK_MEM_INVALID type: %d at 0x%" PRIu64 "\n", log_num++, type, addr);
         return false;
      case UC_MEM_WRITE_RO:
         printf("# RO memory is being WRITTEN at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);

         if (uc_mem_read(handle, DATA_SECTION, bytes, sizeof(bytes)) != UC_ERR_OK) {
            printf("not ok %d - uc_mem_read fail for address: 0x%" PRIu64 "\n", log_num++, addr);
            _exit(1);
         }
         printf("ok %d - uc_mem_read for ro side of test %d\n", log_num++, test_num - 1);

         if (memcmp(bytes, tests[test_num - 1], sizeof(bytes)) == 0) {
            printf("ok %d - passed ro side of test %d\n", log_num++, test_num - 1);
         }
         else {
            printf("ok %d - failed ro side of test %d\n", log_num++, test_num - 1);
            hexdump("# Expected: ", tests[test_num - 1], sizeof(bytes));
            hexdump("# Received: ", bytes, sizeof(bytes));
         }         

         current_perms |= UC_PROT_WRITE;
         if (uc_mem_protect(handle, DATA_SECTION, DATA_SIZE, current_perms) != UC_ERR_OK) {
            printf("not ok %d - uc_mem_protect fail during hook_mem_invalid callback, addr: 0x%" PRIu64 "\n", log_num++, addr);
            _exit(1);
         }
         else {
            printf("ok %d - uc_mem_protect UC_PROT_WRITE toggled\n", log_num++);
         }
         return true;
   }
}

int main(int argc, char **argv, char **envp) {
   uch handle, trace1, trace2;
   uc_err err;
   uint8_t bytes[8];
   uint32_t esp;
   int result;
   
   printf("# Memory protect test\n");
   
   // Initialize emulator in X86-32bit mode
   err = uc_open(UC_ARCH_X86, UC_MODE_32, &handle);
   if (err) {
      printf("not ok %d - Failed on uc_open() with error returned: %u\n", log_num++, err);
      return 1;
   }
   else {
      printf("ok %d - uc_open() success\n", log_num++);
   }
   
   uc_mem_map_ex(handle, CODE_SECTION, CODE_SIZE, UC_PROT_READ);
   uc_mem_map_ex(handle, DATA_SECTION, DATA_SIZE, current_perms);
   
   // write machine code to be emulated to memory
   if (uc_mem_write(handle, CODE_SECTION, PROGRAM, sizeof(PROGRAM))) {
      printf("not ok %d - Failed to write emulation code to memory, quit!\n", log_num++);
      return 2;
   }
   else {
      printf("ok %d - Program written to memory\n", log_num++);
   }
   
   if (uc_hook_add(handle, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK) {
      printf("not ok %d - Failed to install UC_HOOK_CODE handler\n", log_num++);
      return 3;
   }
   else {
      printf("ok %d - UC_HOOK_CODE installed\n", log_num++);
   }
   
   // intercept invalid memory events
   if (uc_hook_add(handle, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL) != UC_ERR_OK) {
      printf("not ok %d - Failed to install UC_HOOK_MEM_INVALID handler\n", log_num++);
      return 4;
   }
   else {
      printf("ok %d - UC_HOOK_MEM_INVALID installed\n", log_num++);
   }
   
   // emulate machine code until told to stop by hook_code
   printf("# BEGIN execution\n");
   err = uc_emu_start(handle, CODE_SECTION, CODE_SECTION + CODE_SIZE, 0, 100);
   if (err != UC_ERR_OK) {
      printf("not ok %d - Failure on uc_emu_start() with error %u:%s\n", log_num++, err, uc_strerror(err));
      return 5;
   }
   else {
      printf("ok %d - uc_emu_start complete\n", log_num++);
   }
   printf("# END execution\n");
      
   if (uc_close(&handle) == UC_ERR_OK) {
      printf("ok %d - uc_close complete\n", log_num++);
   }
   else {
      printf("not ok %d - uc_close complete\n", log_num++);
   }
   
   return 0;
}
