CFLAGS += -Wall -Werror -Wno-unused-function -g
CFLAGS += -L ../../ -I ../../include
CFLAGS += -L ../../cmocka/src -I ../../cmocka/include
LDLIBS += -lcmocka -lunicorn

EXECUTE_VARS = LD_LIBRARY_PATH=../../cmocka/src:../../ DYLD_LIBRARY_PATH=../../

ifeq ($(UNICORN_ASAN),yes)
CC = clang -fsanitize=address -fno-omit-frame-pointer
CXX = clang++ -fsanitize=address -fno-omit-frame-pointer
AR = llvm-ar
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

ALL_TESTS_SOURCES = $(wildcard *.c)
ALL_TESTS = $(ALL_TESTS_SOURCES:%.c=%)

.PHONY: all
all: ${ALL_TESTS}

.PHONY: clean
clean:
	rm -rf ${ALL_TESTS}

.PHONY: test
test: ${ALL_TESTS}
	${EXECUTE_VARS} ./test_sanity
	${EXECUTE_VARS} ./test_x86
	${EXECUTE_VARS} ./test_mem_map
	${EXECUTE_VARS} ./test_mem_map_ptr
	${EXECUTE_VARS} ./test_mem_high
	${EXECUTE_VARS} ./test_multihook
	${EXECUTE_VARS} ./test_pc_change
	${EXECUTE_VARS} ./test_hookcounts
	echo "skipping test_tb_x86"
	echo "skipping test_x86_soft_paging"
	echo "skipping test_hang"
	echo "skipping test_x86_sh1_enter_leave"
	echo "skipping test_x86_rip_bug"
