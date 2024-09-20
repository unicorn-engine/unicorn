#!/bin/bash
docker build -t unicorn-builder . || exit 0
docker run -it --rm \
    -e EDITOR=vi \
    -v "$(pwd)":/unicorn \
    -w /unicorn/build \
    --entrypoint bash \
    unicorn-builder \
    -c "cmake .. -DCMAKE_BUILD_TYPE=Release && make"

echo exit $?
