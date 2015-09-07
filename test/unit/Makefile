
CFLAGS += -L ../../
CFLAGS += -lcmocka -lunicorn
CFLAGS += -I ../../include

ALL_TESTS = test_x86 test_mem_map

.PHONY: all
all: ${ALL_TESTS}

.PHONY: clean
clean:
	rm ${ALL_TESTS}

.PHONY: test
test: export LD_LIBRARY_PATH=../../
test: ${ALL_TESTS}
	@#echo ${ALL_TESTS} | xargs -n1 | xargs -I CMD  sh -c ./CMD
	@for test in ${ALL_TESTS}; do  \
		echo -e "\n--------------------------------------------------------------------------------"; \
		echo "TEST: $$test"; \
		./$$test || break; \
	done


test_x86: test_x86.c
test_mem_map: test_mem_map.c

${ALL_TESTS}:
	gcc ${CFLAGS} -o $@ $^



