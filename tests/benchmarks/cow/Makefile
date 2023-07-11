CFLAGS += -Wall -Werror -I../../../include
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
LDLIBS += -L../../../build -lgsl -lgslcblas -lm -lunicorn

UNAME_S := $(shell uname -s)
LDLIBS += -pthread
ifeq ($(UNAME_S), Linux)
LDLIBS += -lrt
endif

#EXECUTE_VARS = LD_LIBRARY_PATH=../../cmocka/src:../../build/ DYLD_LIBRARY_PATH=../../build/
EXECUTE_VARS = LD_LIBRARY_PATH=../../../build/cmocka/src:../../../build/ DYLD_LIBRARY_PATH=../../../build/

TESTS_SOURCE = $(wildcard *.c)
TESTS = $(TESTS_SOURCE:%.c=%)

.PHONY: all clean test

test: $(TESTS)

all: $(TESTS)

clean:
	rm -f $(TESTS)
