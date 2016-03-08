#include <unicorn/unicorn.h>

#define GS16_VALUE 0x1122
#define FS16_VALUE 0x3344
#define GS32_VALUE 0x11223344
#define FS32_VALUE 0x55667788
#define GS64_VALUE 0x9900112233445566
#define FS64_VALUE 0x7788990011223344

int test_reg16_value (uc_engine *uc, int regid, uint16_t value, uint16_t expected) {
  
  uc_err err;

  err = x86_reg_write(uc, regid, &value);
  if (err != UC_ERR_OK) {
    printf("Failed on x86_reg_write() with error returned: %u\n", err);
    return -1;
  }

  err = x86_reg_read(uc, regid, &value);
  if (err != UC_ERR_OK) {
    printf("Failed on x86_reg_read() with error returned: %u\n", err);
    return -1;
  }

  if (value != expected) {
    printf("Error : Wrong reg value in UC_MODE_16. (Got %#x, expected %#x)\n", value, expected);
    return -1;
  }

  return 0;
}

int test_reg32_value (uc_engine *uc, int regid, uint32_t value, uint32_t expected) {
  
  uc_err err;

  err = x86_reg_write(uc, regid, &value);
  if (err != UC_ERR_OK) {
    printf("Failed on x86_reg_write() with error returned: %u\n", err);
    return -1;
  }

  err = x86_reg_read(uc, regid, &value);
  if (err != UC_ERR_OK) {
    printf("Failed on x86_reg_read() with error returned: %u\n", err);
    return -1;
  }

  if (value != expected) {
    printf("Error : Wrong reg value in UC_MODE_32. (Got %#x, expected %#x)\n", value, expected);
    return -1;
  }

  return 0;
}

int test_reg64_value (uc_engine *uc, int regid, uint64_t value, uint64_t expected) {
  
  uc_err err;

  if ((err = x86_reg_write(uc, regid, &value)) != UC_ERR_OK) {
    printf("Failed on x86_reg_write() with error returned: %u\n", err);
    return -1;
  }

  if ((err = x86_reg_read(uc, regid, &value)) != UC_ERR_OK) {
    printf("Failed on x86_reg_read() with error returned: %u\n", err);
    return -1;
  }

  if (value != expected) {
    printf("Error : Wrong reg value in UC_MODE_64. (Got %#llx, expected %#llx)\n", value, expected);
    return -1;
  }

  return 0;
}

int main(int argc, char **argv, char **envp)
{
  uc_engine *uc;
  uc_err err;
  uint16_t gs16 = GS16_VALUE;
  uint16_t fs16 = FS16_VALUE;
  uint32_t gs32 = GS32_VALUE;
  uint32_t fs32 = FS32_VALUE;
  uint64_t gs64 = GS64_VALUE;
  uint64_t fs64 = FS64_VALUE;

  // ====== Test UC_MODE_16 ======
  err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }
  if (test_reg16_value(uc, UC_X86_REG_FS, fs16, FS16_VALUE) < 0) {
    printf("Failed on test_reg16_value() for FS in UC_MODE_16.\n");
    return -1;
  }
  if (test_reg16_value(uc, UC_X86_REG_GS, gs16, GS16_VALUE) < 0) {
    printf("Failed on test_reg16_value() for GS in UC_MODE_16.\n");
    return -1;
  }
  uc_close(uc);

  // ====== Test UC_MODE_32 ======
  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }
  if (test_reg32_value(uc, UC_X86_REG_FS, fs32, FS32_VALUE) < 0) {
    printf("Failed on test_reg32_value() for FS in UC_MODE_32.\n");
    return -1;
  }
  if (test_reg32_value(uc, UC_X86_REG_GS, gs32, GS32_VALUE) < 0) {
    printf("Failed on test_reg32_value() for GS in UC_MODE_32.\n");
    return -1;
  }
  uc_close(uc);

  // ====== Test UC_MODE_64 ======
  err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }
  if (test_reg64_value(uc, UC_X86_REG_FS, fs64, FS64_VALUE) < 0) {
    printf("Failed on test_reg64_value() for FS in UC_MODE_64.\n");
    return -1;
  }
  if (test_reg64_value(uc, UC_X86_REG_GS, gs64, GS64_VALUE) < 0) {
    printf("Failed on test_reg64_value() for GS in UC_MODE_64.\n");
    return -1;
  }
  uc_close(uc);

  return 0;
}