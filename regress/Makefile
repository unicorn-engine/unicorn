CFLAGS += -I../include
LDFLAGS = -L.. -lunicorn

TESTS = map_crash map_write
TESTS += sigill sigill2
TESTS += block_test
TESTS += ro_mem_test nr_mem_test
TESTS += timeout_segfault

all: $(TESTS)

clean:
	rm -f $(TESTS)

.PHONY: all clean
