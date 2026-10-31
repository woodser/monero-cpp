#!/bin/bash

# use the same OpenSSL for monero-project and monero-cpp on macOS
OPENSSL_ARGS=()
if [[ $(uname -s) == "Darwin" ]]; then
    OPENSSL_PREFIX=${OPENSSL_ROOT_DIR:-}
    if [ -z "$OPENSSL_PREFIX" ] && command -v brew >/dev/null 2>&1; then
        OPENSSL_PREFIX=$(brew --prefix openssl@3) || exit 1
        if [ ! -d "$OPENSSL_PREFIX/include/openssl" ]; then
            echo "Install openssl@3 with Homebrew or set OPENSSL_ROOT_DIR to a compatible OpenSSL installation" >&2
            exit 1
        fi
    fi
    if [ -n "$OPENSSL_PREFIX" ]; then
        OPENSSL_ARGS=(-DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX")
    fi
fi

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
    # OS is not windows; explicit ARCH avoids -march=native (CPU-specific binaries)
    case $(uname -m) in
        x86_64) ARCH="x86-64";;
        arm64|aarch64) ARCH="armv8-a";;
        *) ARCH="native";;
    esac
    ( mkdir -p build/release &&
      cd build/release &&
      cmake -D STATIC=ON -D ARCH="$ARCH" -D BUILD_64=ON -D CMAKE_BUILD_TYPE=Release -D USE_DEVICE_TREZOR=OFF "${OPENSSL_ARGS[@]}" ../../ &&
      make -j$HOST_NCORES wallet cryptonote_protocol ) || exit 1
fi
cd ../../

# build libmonero-cpp shared library; extra args go to cmake, e.g. -D BUILD_SAMPLE=ON
mkdir -p build &&
cd build &&
cmake "${OPENSSL_ARGS[@]}" "$@" .. &&
cmake --build . -j$HOST_NCORES
