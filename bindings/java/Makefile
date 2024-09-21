# Makefile for the native JNI library. Automatically called by Maven.

JAVA_HOME ?= $(shell java -XshowSettings:properties -version 2>&1 | sed -n 's/ *java.home = //p')

ifeq ($(JAVA_HOME),)
  $(error JAVA_HOME could not be determined; please set it manually (make JAVA_HOME=...))
endif

JAVA_INC := $(JAVA_HOME)/include
JAVA_PLATFORM_INC := $(shell dirname `find $(JAVA_INC) -name jni_md.h`)
UNICORN_INC := ../../include

OS := $(shell uname)
ifeq ($(OS),Darwin)
   LIB_EXT=.dylib
else ifeq ($(OS),Linux)
   LIB_EXT=.so
else
   LIB_EXT=.dll
endif

all: libunicorn_java$(LIB_EXT)

CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -fPIC
# May also use -lunicorn to dynamically link against the installed unicorn
LIBS=../../build/libunicorn.a
INCS=-I target/headers -I$(JAVA_INC) -I$(JAVA_PLATFORM_INC) -I$(UNICORN_INC)

OBJS=unicorn_Unicorn.o

unicorn_Unicorn.o: unicorn_Unicorn.c target/headers/unicorn_Unicorn.h
	$(CC) -O2 -Wall -Wextra -Wno-unused-parameter -c $(CFLAGS) $(INCS) $< -o $@

libunicorn_java$(LIB_EXT): $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

gen_const:
	cd .. && python3 const_generator.py java

clean:
	rm -f libunicorn_java$(LIB_EXT)
	rm -f $(OBJS)

.PHONY: all clean
