CFLAGS += -L ../../ -I ../../include

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
LDFLAGS += -lrt -pthread
endif

LDFLAGS += -lunicorn

EXECUTE_VARS = LD_LIBRARY_PATH=../../ DYLD_LIBRARY_PATH=../../

ALL_TESTS_SOURCES = $(wildcard fuzz*.c)
ALL_TESTS = $(ALL_TESTS_SOURCES:%.c=%)

.PHONY: all
all: ${ALL_TESTS}

.PHONY: clean
clean:
	rm -rf ${ALL_TESTS}

fuzz%: fuzz%.c
	$(CC) $(CFLAGS) $^ onefile.c $(LDFLAGS) -o $@

.PHONY:test
test: all
	${EXECUTE_VARS} ./fuzz_emu_arm64_arm
	${EXECUTE_VARS} ./fuzz_emu_arm64_armbe
	${EXECUTE_VARS} ./fuzz_emu_arm_arm
	${EXECUTE_VARS} ./fuzz_emu_arm_armbe
	${EXECUTE_VARS} ./fuzz_emu_arm_thumb
	${EXECUTE_VARS} ./fuzz_emu_arm_thumbbe
	${EXECUTE_VARS} ./fuzz_emu_m68k_be
	${EXECUTE_VARS} ./fuzz_emu_mips_32be
	${EXECUTE_VARS} ./fuzz_emu_mips_32le
	${EXECUTE_VARS} ./fuzz_emu_sparc_32
	${EXECUTE_VARS} ./fuzz_emu_sparc_32be
	${EXECUTE_VARS} ./fuzz_emu_sparc_64be
	${EXECUTE_VARS} ./fuzz_emu_x86_16
	${EXECUTE_VARS} ./fuzz_emu_x86_32
	${EXECUTE_VARS} ./fuzz_emu_x86_64
