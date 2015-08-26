CFLAGS += -I../include
LDFLAGS = -L.. -lunicorn

TESTS = map_crash sigill sigill2 block_test ro_mem_test

all: $(TESTS)

clean:
	rm -f $(TESTS)

.PHONY: all clean
