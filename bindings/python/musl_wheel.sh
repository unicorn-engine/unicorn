#!/bin/sh

# TODO: use cibuildwheel
apk update
apk add gcc make cmake pkgconfig linux-headers git musl-dev patchelf

python3 -m pip install -U pip setuptools auditwheel

cd bindings/python && python3 setup.py bdist_wheel && auditwheel repair dist/*.whl && mv -f wheelhouse/*.whl ./dist/