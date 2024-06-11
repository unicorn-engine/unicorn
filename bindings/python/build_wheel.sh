#!/bin/bash
set -e -x

cd bindings/python

# Compile wheels
python3.7 setup.py bdist_wheel $@
cd dist

# We can't repair an aarch64 wheel on x64 hosts
# https://github.com/pypa/auditwheel/issues/244
if [[ ! "$*" =~ "aarch64" ]];then
  auditwheel repair *.whl
  mv -f wheelhouse/*.whl .
fi
