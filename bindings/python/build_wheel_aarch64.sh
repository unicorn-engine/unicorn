#!/bin/bash

yum install python3 -y
python3 -m pip install -U setuptools wheel auditwheel
cd /work/bindings/python
python3 setup.py bdist_wheel

cd dist
auditwheel repair *.whl
mv -f wheelhouse/*.whl .
