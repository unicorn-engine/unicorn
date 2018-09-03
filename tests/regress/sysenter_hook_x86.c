#include <unicorn/unicorn.h>

// code to be emulated
#define X86_CODE32 "\x0F\x34" // SYSENTER

// memory address where emulation starts
#define ADDRESS 0x1000000

int got_sysenter = 0;

void sysenter (uc_engine *uc, void *user) {
    printf ("SYSENTER hook called.\n");
    got_sysenter = 1;
}

int main(int argc, char **argv, char **envp)
{
  uc_engine *uc;
  uc_err err;
  uc_hook sysenterHook;

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
    printf("Failed to write emulation code to memory, quit!\n");
    return -1;
  }

  // Hook the SYSENTER instructions
  if (uc_hook_add (uc, &sysenterHook, UC_HOOK_INSN, sysenter, NULL, 1, 0, UC_X86_INS_SYSENTER) != UC_ERR_OK) {
      printf ("Cannot hook SYSENTER instruction\n.");
      return -1;
  }

  // emulate code in infinite time & unlimited instructions
  err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n",
      err, uc_strerror(err));
  }

  printf("Emulation done.\n");
  uc_close(uc);

  if (!got_sysenter) {
    printf ("[!] ERROR : SYSENTER hook not called.\n");
    return -1;
  }

  return 0;
}
