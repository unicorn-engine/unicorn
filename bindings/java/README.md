This documentation explains how to install the Java binding for Unicorn
from source.

0. Follow `docs/COMPILE.md` in the root directory to compile the core to the `build` directory.

   Note: by default, the Java binding native library will be built by statically linking to
   `../../build/libunicorn.a`, thereby removing `libunicorn` as a runtime dependency, but
   making the produced native library `libunicorn_java` bigger.

   If you instead want to dynamically link against the installed `libunicorn`, change
   `LIBS=../../build/libunicorn.a` to `LIBS=-lunicorn` in `Makefile`.

1. Install a JDK for your platform.

2. Install Maven: https://maven.apache.org/install.html.

3. Change directories into the java bindings and build the Maven package:

        $ mvn package

This will automatically build and test the Unicorn Java bindings.

The bindings consist of the native JNI library (`libunicorn_java.{so,dylib,dll}`)
and the Java JAR (`target/unicorn-2.xx.jar`). You will need to have the native
library on `java.library.path` and the JAR on your classpath.

The `src/main/test/java` directory contains some sample code to show how to use Unicorn API.
`samples` is a set of sample classes showcasing the various features of the Unicorn API,
while `tests` is a set of JUnit tests for the API.

- `Sample_<arch>.java`:
  These show how to access architecture-specific information for each
  architecture.

- `Shellcode.java`:
  This shows how to analyze a Linux shellcode.

- `SampleNetworkAuditing.java`:
  Unicorn sample for auditing network connection and file handling in shellcode.
