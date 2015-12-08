
CFLAGS += -Wall -Werror -Wno-unused-function -g
CFLAGS += -L ../../
CFLAGS += -lcmocka -lunicorn
CFLAGS += -I ../../include

ALL_TESTS = test_sanity test_x86 test_mem_map test_mem_high

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

test_sanity: test_sanity.c
test_x86: test_x86.c
test_mem_map: test_mem_map.c
test_mem_high: test_mem_high.c

${ALL_TESTS}:
	gcc ${CFLAGS} -o $@ $^



