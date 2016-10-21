#!/bin/sh
set -ex
mkdir cmocka
wget https://cmocka.org/files/1.1/cmocka-1.1.0.tar.xz -O /tmp/cmocka-1.1.0.tar.xz
tar -xf /tmp/cmocka-1.1.0.tar.xz -C /tmp
cd cmocka && cmake /tmp/cmocka-1.1.0 && make
#cmocka does not include headers in build
cp -R /tmp/cmocka-1.1.0/include/ .
