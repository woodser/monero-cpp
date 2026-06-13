#!/bin/sh

# build monero-project dependencies
cd ./external/monero-project/ || exit 1
git submodule update --init --force || exit 1
HOST_NCORES=$(nproc 2>/dev/null || shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
if [[ $(uname -s) == "MINGW64_NT"* || $(uname -s) == "MSYS"* ]]; then
    bit=$(getconf LONG_BIT)
    FOLDER=$(cd ${MINGW_PREFIX}/.. && pwd -W)
    if [ "$bit" == "64" ]; then
        ( mkdir -p build/release &&
          cd build/release &&
          cmake -G "MSYS Makefiles" \
            -D STATIC=ON \
            -D ARCH="x86-64" \
            -D BUILD_64=ON \
            -D CMAKE_BUILD_TYPE=Release \
            -D BUILD_TAG="win-x64" \
            -D CMAKE_TOOLCHAIN_FILE=../../cmake/64-bit-toolchain.cmake \
            -D MSYS2_FOLDER="$FOLDER" \
            -D USE_DEVICE_TREZOR=OFF \
            ../../ &&
          make -j$HOST_NCORES wallet cryptonote_protocol ) || exit 1
    else
        ( mkdir -p build/release &&
          cd build/release &&
          cmake -G "MSYS Makefiles" \
            -D STATIC=ON \
            -D ARCH="i686" \
            -D BUILD_64=OFF \
            -D CMAKE_BUILD_TYPE=Release \
            -D BUILD_TAG="win-x32" \
            -D CMAKE_TOOLCHAIN_FILE=../../cmake/32-bit-toolchain.cmake \
            -D MSYS2_FOLDER="$FOLDER" \
            -D USE_DEVICE_TREZOR=OFF \
            ../../ &&
          make -j$HOST_NCORES wallet cryptonote_protocol ) || exit 1
    fi
else
    # OS is not windows
    ( mkdir -p build/release &&
      cd build/release &&
      cmake -DCMAKE_BUILD_TYPE=Release ../../ &&
      make -j$HOST_NCORES wallet cryptonote_protocol ) || exit 1
fi
cd ../../

# build libmonero-cpp shared library
mkdir -p build && 
cd build && 
cmake .. && 
cmake --build . && 
make .