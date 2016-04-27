
CFLAGS += -Wall -Werror -Wno-unused-function -g
CFLAGS += -L ../../
CFLAGS += -lcmocka -lunicorn
CFLAGS += -I ../../include

ifeq ($(UNICORN_ASAN),yes)
CC = clang -fsanitize=address -fno-omit-frame-pointer
CXX = clang++ -fsanitize=address -fno-omit-frame-pointer
AR = llvm-ar
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

ALL_TESTS = test_sanity test_x86 test_mem_map test_mem_high test_mem_map_ptr \
	test_tb_x86 test_multihook test_pc_change test_x86_soft_paging \
        test_hookcounts

.PHONY: all
all: ${ALL_TESTS}

.PHONY: clean
clean:
	rm -rf ${ALL_TESTS}

.PHONY: test
test: export LD_LIBRARY_PATH=../../
test: ${ALL_TESTS}
	./test_sanity
	./test_x86
	./test_mem_map
	./test_mem_map_ptr
	./test_mem_high
	./test_tb_x86
	./test_multihook
	./test_pc_change
	./test_x86_soft_paging
	./test_hookcounts

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

${ALL_TESTS}:
	${CC} ${CFLAGS} -o $@ $^
