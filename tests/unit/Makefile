CFLAGS += -Wall -Werror -Wno-unused-function -g
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
CFLAGS += -L ../../ -I ../../include
CFLAGS += -L ../../cmocka/src -I ../../cmocka/include
CFLAGS += -L /usr/local/lib -I /usr/local/include
ASFLAGS += --32
OBJCOPY = objcopy

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
LDLIBS += -pthread
ifeq ($(UNAME_S), Linux)
LDLIBS += -lrt
else ifeq ($(UNAME_S), Darwin)
OBJCOPY = gobjcopy
ASFLAGS = -arch i386
endif

LDLIBS += -lcmocka -lunicorn

EXECUTE_VARS = LD_LIBRARY_PATH=../../cmocka/src:../../ DYLD_LIBRARY_PATH=../../

ifeq ($(UNICORN_ASAN),yes)
CC = clang -fsanitize=address -fno-omit-frame-pointer
CXX = clang++ -fsanitize=address -fno-omit-frame-pointer
AR = llvm-ar
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

ALL_TESTS_SOURCES = $(wildcard *.c)
TEST_ASSEMBLY = $(wildcard *.s)
TEST_PROGS = $(TEST_ASSEMBLY:%.s=%.o)
TEST_BINS = $(TEST_PROGS:%.o=%.bin)
ALL_TESTS = $(ALL_TESTS_SOURCES:%.c=%)

ifneq (,$(findstring x86,$(UNAME_M)))
ALL_TESTS += $(TEST_BINS)
endif

.PHONY: all
all: ${ALL_TESTS}

.PHONY: clean
clean:
	rm -rf ${ALL_TESTS}

%.bin: %.o
	${OBJCOPY} -O binary $^ $@
	hexdump -C $@

.PHONY: test
test: all 
	${EXECUTE_VARS} ./test_sanity
	${EXECUTE_VARS} ./test_x86
	${EXECUTE_VARS} ./test_mem_map
	${EXECUTE_VARS} ./test_mem_map_ptr
	${EXECUTE_VARS} ./test_mem_high
	${EXECUTE_VARS} ./test_multihook
	${EXECUTE_VARS} ./test_pc_change
	${EXECUTE_VARS} ./test_hookcounts
	${EXECUTE_VARS} ./test_x86_fxsave_fpip
	echo "skipping test_tb_x86"
	echo "skipping test_x86_soft_paging"
	echo "skipping test_hang"
	echo "skipping test_x86_sh1_enter_leave"
	echo "skipping test_x86_rip_bug"
