#!/bin/bash
set -ex
mkdir cmocka
wget https://cmocka.org/files/1.1/cmocka-1.1.0.tar.xz -O /tmp/cmocka-1.1.0.tar.xz
tar -xvf /tmp/cmocka-1.1.0.tar.xz -C /tmp
if [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ] ; then
cd cmocka && which cmake && cmake -G "MinGW Makefiles" /tmp/cmocka-1.1.0 && make
else
cd cmocka && cmake /tmp/cmocka-1.1.0 && make
fi
#cmocka does not include headers in build
cp -R /tmp/cmocka-1.1.0/include/ .
