#!/bin/bash
set -e -x

cd bindings/python

# Compile wheels
if [ -f /opt/python/cp36-cp36m/bin/python ];then
  /opt/python/cp36-cp36m/bin/python setup.py bdist_wheel $@
else
  python3 setup.py bdist_wheel $@
fi
cd dist

# We can't repair an aarch64 wheel on x64 hosts
# https://github.com/pypa/auditwheel/issues/244
if [[ ! "$*" =~ "aarch64" ]];then
  auditwheel repair *.whl
  mv -f wheelhouse/*.whl .
fi