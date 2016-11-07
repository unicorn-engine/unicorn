CFLAGS += -Wall -Werror -I../../include
LDLIBS += -L../../ $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn

EXECUTE_VARS = LD_LIBRARY_PATH=../../cmocka/src:../../ DYLD_LIBRARY_PATH=../../

TESTS_SOURCE = $(wildcard *.c)
TESTS = $(TESTS_SOURCE:%.c=%)

.PHONY: all clean test

test: $(TESTS)

all: $(TESTS)

clean:
	rm -f $(TESTS)
