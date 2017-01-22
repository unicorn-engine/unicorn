/*

rep movsb   regression 

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#define __STDC_FORMAT_MACROS
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unicorn/unicorn.h>

unsigned char PROGRAM[] =
   "\xbe\x00\x00\x20\x00\xbf\x00\x10\x20\x00\xb9\x14\x00\x00\x00\xf3"
   "\xa4\xf4";
// total size: 18 bytes

/*
bits 32

; assumes code section at 0x100000  r-x
; assumes data section at 0x200000-0x202000, rw-

mov  esi, 0x200000
mov  edi, 0x201000
mov  ecx, 20
rep movsb
hlt
*/

static int log_num = 1;

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data)
{
   uint8_t opcode;
   if (uc_mem_read(uc, addr, &opcode, 1) != UC_ERR_OK) {
      printf("not ok %d - uc_mem_read fail during hook_code callback, addr: 0x%" PRIx64 "\n", log_num++, addr);
      _exit(-1);
   }
   switch (opcode) {
      case 0xf4:  //hlt
         printf("# Handling HLT\n");
         if (uc_emu_stop(uc) != UC_ERR_OK) {
            printf("not ok %d - uc_emu_stop fail during hook_code callback, addr: 0x%" PRIx64 "\n", log_num++, addr);
            _exit(-1);
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
static void hook_mem_write(uc_engine *uc, uc_mem_type type,
        uint64_t addr, int size, int64_t value, void *user_data)
{
   printf("# write to memory at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
   if (addr < 0x201000L) {
      //this is actually a read, we don't write in this range
      printf("not ok %d - write hook called for read of 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", log_num++, addr, size, value);
   }
   else {
      printf("ok %d - write hook called for write of 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", log_num++, addr, size, value);
   }
}

int main(int argc, char **argv, char **envp)
{
   uc_engine *uc;
   uc_hook trace1, trace2;
   uc_err err;
   uint8_t buf1[100], readbuf[100];
   
   printf("# rep movsb test\n");

   memset(buf1, 'A', 20);

   // Initialize emulator in X86-32bit mode
   err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
   if (err) {
      printf("not ok %d - Failed on uc_open() with error returned: %u\n", log_num++, err);
      return 1;
   }
   else {
      printf("ok %d - uc_open() success\n", log_num++);
   }

   uc_mem_map(uc, 0x100000, 0x1000, UC_PROT_READ);
   uc_mem_map(uc, 0x200000, 0x2000, UC_PROT_READ | UC_PROT_WRITE);

   // fill in the data that we want to copy
   if (uc_mem_write(uc, 0x200000, buf1, 20)) {
      printf("not ok %d - Failed to write read buffer to memory, quit!\n", log_num++);
      return 2;
   }
   else {
      printf("ok %d - Read buffer written to memory\n", log_num++);
   }

   // write machine code to be emulated to memory
   if (uc_mem_write(uc, 0x100000, PROGRAM, sizeof(PROGRAM))) {
      printf("not ok %d - Failed to write emulation code to memory, quit!\n", log_num++);
      return 4;
   }
   else {
      printf("ok %d - Program written to memory\n", log_num++);
   }

   if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK) {
      printf("not ok %d - Failed to install UC_HOOK_CODE handler\n", log_num++);
      return 5;
   }
   else {
      printf("ok %d - UC_HOOK_CODE installed\n", log_num++);
   }

   // intercept memory write events only, NOT read events
   if (uc_hook_add(uc, &trace1, UC_HOOK_MEM_WRITE, hook_mem_write, NULL, 1, 0) != UC_ERR_OK) {
      printf("not ok %d - Failed to install UC_HOOK_MEM_WRITE handler\n", log_num++);
      return 6;
   }
   else {
      printf("ok %d - UC_HOOK_MEM_WRITE installed\n", log_num++);
   }

   // emulate machine code until told to stop by hook_code
   printf("# BEGIN execution\n");
   err = uc_emu_start(uc, 0x100000, 0x101000, 0, 0);
   if (err != UC_ERR_OK) {
      printf("not ok %d - Failure on uc_emu_start() with error %u:%s\n", log_num++, err, uc_strerror(err));
      return 8;
   }
   else {
      printf("ok %d - uc_emu_start complete\n", log_num++);
   }
   printf("# END execution\n");

   //make sure that data got copied
   // fill in sections that shouldn't get touched
   if (uc_mem_read(uc, 0x201000, readbuf, 20)) {
      printf("not ok %d - Failed to read random buffer 1 from memory\n", log_num++);
   }
   else {
      printf("ok %d - Random buffer 1 read from memory\n", log_num++);
      if (memcmp(buf1, readbuf, 20)) {
         printf("not ok %d - write buffer contents are incorrect\n", log_num++);
      }
      else {
         printf("ok %d - write buffer contents are correct\n", log_num++);
      }
   }

   if (uc_close(uc) == UC_ERR_OK) {
      printf("ok %d - uc_close complete\n", log_num++);
   }
   else {
      printf("not ok %d - uc_close complete\n", log_num++);
   }

   return 0;
}
