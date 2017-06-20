#!/bin/sh -ex
mkdir -p cmocka
#wget https://cmocka.org/files/1.1/cmocka-1.1.0.tar.xz -O /tmp/cmocka-1.1.0.tar.xz
wget --no-check-certificate http://cmocka.org/files/1.1/cmocka-1.1.1.tar.xz -O /tmp/
tar -xf /tmp/cmocka-1.1.1.tar.xz -C /tmp
pushd cmocka && cmake -DUNIT_TESTING=On /tmp/cmocka-1.1.1 && make && make test
# cmake builds an so instead of a dll in mingw/msys
if [[ ! -z $MSYSTEM ]]; then
cp src/cmocka.so src/cmocka.dll
fi
# cmocka does not include headers in build
cp -R /tmp/cmocka-1.1.0/include/ .
