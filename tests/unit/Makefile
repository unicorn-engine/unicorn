
CFLAGS += -Wall -Werror -Wno-unused-function -g
CFLAGS += -L ../../
CFLAGS += -I ../../include
CFLAGS += -L ../../cmocka/src -I ../../cmocka/include
EXECUTE_VARS = LD_LIBRARY_PATH=../../cmocka/src:../../ DYLD_LIBRARY_PATH=../../

LIBS += -lcmocka -lunicorn

ifeq ($(UNICORN_ASAN),yes)
CC = clang -fsanitize=address -fno-omit-frame-pointer
CXX = clang++ -fsanitize=address -fno-omit-frame-pointer
AR = llvm-ar
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

ALL_TESTS = test_sanity test_x86 test_mem_map test_mem_high test_mem_map_ptr \
	test_tb_x86 test_multihook test_pc_change test_x86_soft_paging \
        test_hookcounts test_hang test_x86_shl_enter_leave test_x86_rip_bug

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
	echo "skipping test_tb_x86" #${EXECUTE_VARS} ./test_tb_x86
	${EXECUTE_VARS} ./test_multihook
	${EXECUTE_VARS} ./test_pc_change
	echo "skipping test_x86_soft_paging" #${EXECUTE_VARS} ./test_x86_soft_paging
	${EXECUTE_VARS} ./test_hookcounts
	echo "skipping test_hang" #${EXECUTE_VARS} ./test_hang
	echo "skipping test_x86_sh1_enter_leave" #${EXECUTE_VARS} ./test_x86_shl_enter_leave
	echo "skipping test_x86_rip_bug" #${EXECUTE_VARS} ./test_x86_rip_bug

test_sanity: test_sanity.c
test_x86: test_x86.c
test_mem_map: test_mem_map.c
test_mem_map_ptr: test_mem_map_ptr.c
test_mem_high: test_mem_high.c
test_tb_x86: test_tb_x86.c
test_multihook: test_multihook.c
test_pc_change: test_pc_change.c
test_x86_soft_paging: test_x86_soft_paging.c
test_hookcounts: test_hookcounts.c
test_hang: test_hang.c
test_x86_shl_enter_leave: test_x86_shl_enter_leave.c
test_x86_rip_bug: test_x86_rip_bug.c

${ALL_TESTS}:
	${CC} ${CFLAGS} -o $@ $^ ${LIBS}
