#include <stdio.h>
#include <unicorn/unicorn.h>

uint64_t starts[] = {0x10000000, 0x110004000ll};

int main(int argc, char **argv, char **envp) {
   uc_engine *uc;
   uc_err err;
   int i;
   // Initialize emulator in X86-64bit mode
   err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
   if (err) {
      printf("Failed on uc_open() with error returned: %u\n", err);
      return 1;
   }

   for (i = 0; i < (sizeof(starts) / sizeof(uint64_t)); i++) {
      uc_mem_map(uc, starts[i], 4096, UC_PROT_ALL);
   }
   
   uint32_t count;
   uc_mem_region *regions;
   int err_count = 0;
   err = uc_mem_regions(uc, &regions, &count);
   if (err == UC_ERR_OK) {
      for (i = 0; i < count; i++) {
         fprintf(stderr, "region %d: 0x%"PRIx64"-0x%"PRIx64" (%d)\n", i, regions[i].begin, regions[i].end - 1, regions[i].perms);
         if (regions[i].begin != starts[i]) {
            err_count++;
            fprintf(stderr, "   ERROR: region start does not match requested start address, expected 0x%"PRIx64", found 0x%"PRIx64"\n",
                    starts[i], regions[i].begin);
         }
      }
      uc_free(regions);
   }
   
   uc_close(uc);
   return err_count;
}
