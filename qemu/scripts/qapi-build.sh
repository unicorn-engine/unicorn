#!/bin/sh

# Run this scripts to create qapi below files in root dir
# ../qapi-types.c
# ../qapi-types.h
# ../qapi-visit.c
# ../qapi-visit.h

python qapi-types.py -h -o .. -b -i qapi-schema.json
python qapi-types.py -c -o .. -b -i qapi-schema.json

python qapi-visit.py -h -o .. -b -i qapi-schema.json
python qapi-visit.py -c -o .. -b -i qapi-schema.json

