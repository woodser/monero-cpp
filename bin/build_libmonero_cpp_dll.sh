#!/bin/sh

HOST_NCORES=$(nproc 2>/dev/null || shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)

# build libmonero-cpp shared library
mkdir -p build && 
cd build && 
cmake .. && 
cmake --build . && 
make .
