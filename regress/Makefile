CFLAGS += -I../include
LDFLAGS = -L.. -lunicorn

TESTS = map_crash map_write
TESTS += sigill sigill2
TESTS += block_test
TESTS += ro_mem_test nr_mem_test
TESTS += timeout_segfault
TESTS += rep_movsb
TESTS += mem_unmap
TESTS += mem_protect
TESTS += mem_exec

all: $(TESTS)

clean:
	rm -f $(TESTS)

.PHONY: all clean
