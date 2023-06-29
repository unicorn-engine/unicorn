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
INCS=-I$(JAVA_INC) -I$(JAVA_PLATFORM_INC) -I$(UNICORN_INC)

OBJS=unicorn_Unicorn.o

unicorn_Unicorn.h: src/main/java/unicorn/Unicorn.java
	javah -cp src/main/java -o $@ unicorn.Unicorn

unicorn_Unicorn.o: unicorn_Unicorn.c unicorn_Unicorn.h
	$(CC) -O2 -Wall -Wextra -Wno-unused-parameter -c $(CFLAGS) $(INCS) $< -o $@

libunicorn_java$(LIB_EXT): $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

clean:
	rm -f libunicorn_java$(LIB_EXT)
	rm -f unicorn_Unicorn.h
	rm -f $(OBJS)

.PHONY: all clean
