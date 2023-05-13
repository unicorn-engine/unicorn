all: jar lib samples

JC=javac

JAVA_HOME := $(shell readlink -f `which $(JC)` | sed "s:/bin/$(JC)::")

JAVA_INC := $(shell realpath $(JAVA_HOME)/include)

JAVA_PLATFORM_INC := $(shell dirname `find $(JAVA_INC) -name jni_md.h`)

UNICORN_INC=../../include

SAMPLES := $(shell ls samples/*.java)
TESTS := $(shell ls tests/*.java)
SRC := $(shell ls unicorn/*.java)

OS := $(shell uname)
ifeq ($(OS),Darwin)
   LIB_EXT=.dylib
else ifeq ($(OS),Linux)
   LIB_EXT=.so
else
   LIB_EXT=.dll
endif

CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -fPIC
LIBS=-lunicorn
LIBDIR=-L../../
INCS=-I$(JAVA_INC) -I$(JAVA_PLATFORM_INC) -I$(UNICORN_INC)

CLASSPATH=./

.SUFFIXES: .java .class

tests/%.class: tests/%.java
	$(JC) -Xlint:deprecation -classpath .:unicorn.jar:testdep/junit-4.13.2.jar $(JFLAGS) $<

%.class: %.java
	$(JC) -Xlint:deprecation -classpath .:unicorn.jar $(JFLAGS) $<

OBJS=unicorn_Unicorn.o

JARFILE=unicorn.jar

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCS) $< -o $@

unicorn_Unicorn.h: unicorn/Unicorn.java
	$(JC) -h . $<

unicorn_Unicorn.o: unicorn_Unicorn.c unicorn_Unicorn.h
	$(CC) -O2 -Wall -Wextra -Wno-unused-parameter -c $(CFLAGS) $(INCS) $< -o $@

libunicorn_java$(LIB_EXT): unicorn_Unicorn.o

lib: libunicorn_java$(LIB_EXT) unicorn_Unicorn.h
	$(CC) -o $< $(LDFLAGS) $(OBJS) $(LIBDIR) $(LIBS)

samples: $(SAMPLES:.java=.class)
tests: $(TESTS:.java=.class)
jarfiles: $(SRC:.java=.class)

jar: jarfiles
	jar cf $(JARFILE) unicorn/*.class

test: lib samples tests
	java -Xcheck:jni -cp .:testdep/hamcrest-2.2.jar:testdep/junit-4.13.2.jar org.junit.runner.JUnitCore $(subst /,.,$(TESTS:.java=))

install: lib jar
	cp libunicorn_java$(LIB_EXT) /usr/lib
	cp $(JARFILE) /usr/share/java

uninstall:
	rm -f /usr/lib/libunicorn_java$(LIB_EXT)
	rm -f /usr/share/java/$(JARFILE)

gen_const:
	cd .. && python3 const_generator.py java

clean:
	rm -f unicorn/*.class
	rm -f samples/*.class
	rm -f *.so
	rm -f *.dylib
	rm -f *.dll

.PHONY: all lib samples jar install uninstall gen_const clean
