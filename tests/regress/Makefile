CFLAGS += -Wall -Werror -I../../include
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
LDLIBS += -L../../ -lm -lunicorn

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
LDLIBS += -lrt -pthread
endif

EXECUTE_VARS = LD_LIBRARY_PATH=../../cmocka/src:../../ DYLD_LIBRARY_PATH=../../

TESTS_SOURCE = $(wildcard *.c)
TESTS = $(TESTS_SOURCE:%.c=%)

.PHONY: all clean test

test: $(TESTS)

all: $(TESTS)

clean:
	rm -f $(TESTS)
