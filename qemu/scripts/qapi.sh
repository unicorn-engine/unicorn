#!/bin/sh

# Run this scripts to create qapi below files in root dir
# ../qapi-types.c
# ../qapi-types.h
# ../qapi-visit.c
# ../qapi-visit.h

python scripts/qapi-types.py -h -o .. -b -i qapi-schema.json
python scripts/qapi-types.py -c -o .. -b -i qapi-schema.json

python scripts/qapi-visit.py -h -o .. -b -i qapi-schema.json
python scripts/qapi-visit.py -c -o .. -b -i qapi-schema.json

