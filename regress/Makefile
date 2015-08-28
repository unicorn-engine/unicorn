CFLAGS += -I../include
LDFLAGS = -L.. -lunicorn

TESTS = map_crash map_write
TESTS += sigill sigill2
TESTS += block_test
TESTS += ro_mem_test mem_protect

all: $(TESTS)

clean:
	rm -f $(TESTS)

.PHONY: all clean
