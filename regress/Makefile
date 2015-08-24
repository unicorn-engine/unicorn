CFLAGS += -I../include
LDFLAGS = -L.. -lunicorn

TESTS = map_crash sigill

all: $(TESTS)

clean:
	rm -f $(TESTS)

.PHONY: all clean
