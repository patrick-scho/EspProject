#!/bin/sh

if [[ "$*" == *"-v"* ]]; then
    set -x
fi

INCLUDES=(
    "-I ext/mjson/src"
    "-I ext/olm/include"
)

LIBPATHS=(
    "-L ext/olm/build"
)

LIBS=(
    "-lolm"
    "-lcurl"
)

OBJS=(
    "out/mjson.o"
)

if [[ "$*" == *"-o"* ]]; then
    gcc -c ext/mjson/src/mjson.c -o out/mjson.o
fi

gcc -o out/main.exe main.c ${INCLUDES[*]} ${LIBPATHS[*]} ${LIBS[*]} ${OBJS[*]}


if [[ "$*" == *"-run"* ]]; then
    out/main.exe
fi