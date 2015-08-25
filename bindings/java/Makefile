JAVA_HOME := $(shell jrunscript -e 'java.lang.System.out.println(java.lang.System.getProperty("java.home"));')

JAVA_INC := $(shell realpath $(JAVA_HOME)/../include)

JAVA_PLATFORM_INC := $(shell dirname `find $(JAVA_INC) -name jni_md.h`)

UNICORN_INC=../../include

SAMPLES := $(shell ls samples/*.java)

CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -fPIC
LIBS=-lunicorn
LIBDIR=-L../../
INCS=-I$(JAVA_INC) -I$(JAVA_PLATFORM_INC) -I$(UNICORN_INC)

JC=javac
CLASSPATH=./

.SUFFIXES: .java .class

%.class: %.java
	$(JC) $(JFLAGS) $<

OBJS=unicorn_Unicorn.o

JARFILE=unicorn.jar

all: lib jar samples

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCS) $< -o $@

unicorn_Unicorn.h: unicorn/Unicorn.java
	javah unicorn.Unicorn
	
unicorn_Unicorn.o: unicorn_Unicorn.c unicorn_Unicorn.h
	$(CC) -c $(CFLAGS) $(INCS) $< -o $@

libunicorn_java.so: unicorn_Unicorn.o

lib: libunicorn_java.so unicorn_Unicorn.h
	$(CC) -o $< $(LDFLAGS) $(OBJS) $(LIBDIR) $(LIBS)

samples: $(SAMPLES:.java=.class)

jar: unicorn/Unicorn.class
	jar cf $(JARFILE) unicorn/*.class 

install: lib jar
	cp -a libunicorn_java.so /usr/local/lib
	cp -a $(JARFILE) $(JAVA_HOME)/lib/ext
