CFLAGS += -lcmocka -lunicorn


ALL_TESTS = test_x86

all: ${ALL_TESTS}

clean:
	rm ${ALL_TESTS}


test_x86: test_x86.c
	gcc ${CFLAGS} -o $@ $^
