#!/bin/sh

export HOST_NCORES=${HOST_NCORES-$(nproc 2>/dev/null || shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)}
BUILD_DIR="$(pwd)/build"
INSTALL_DIR="$BUILD_DIR/install"
export CMAKE_PREFIX_PATH=$INSTALL_DIR${CMAKE_PREFIX_PATH+:$CMAKE_PREFIX_PATH}
export OPENSSL_ROOT_DIR=$INSTALL_DIR
USE_DEVICE_TREZOR=${USE_DEVICE_TREZOR-ON}
echo "HOST_NCORES=$HOST_NCORES in $0"
echo "CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH in $0"
echo "OPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR in $0"
echo "USE_DEVICE_TREZOR=$USE_DEVICE_TREZOR in $0"

[ -d $INSTALL_DIR ] || mkdir -p $INSTALL_DIR

(cd external/boost && \
./bootstrap.sh --prefix=$INSTALL_DIR && ./b2 -j$HOST_NCORES \
--with-chrono \
--with-date_time \
--with-filesystem \
--with-program_options \
--with-regex \
--with-serialization \
--with-system \
--with-thread \
--with-locale \
link=static \
cxxflags=-fPIC cflags=-fPIC \
install) && \

(cd external/openssl && \
./Configure no-apps no-afalgeng no-docs no-ui-console no-shared --prefix=$INSTALL_DIR --libdir=lib && \
make -j$HOST_NCORES && make install) && \

(cd external/libsodium && \
./configure --enable-shared=no --with-pic=yes --prefix=$INSTALL_DIR && \
make -j$HOST_NCORES && make check && make install) && \

(cd external/libexpat/expat && \
./buildconf.sh && ./configure --prefix=$INSTALL_DIR --enable-static --disable-shared --with-pic=yes && \
make -j$HOST_NCORES install) && \

(cd external/unbound && \
./configure --with-ssl=$INSTALL_DIR --prefix=$INSTALL_DIR --with-libexpat=$INSTALL_DIR --enable-static-exe --enable-static --disable-shared --with-pic=yes && \
make -j$HOST_NCORES install) && \

# build monero-project dependencies
cd ./external/monero-project/ || exit 1
git submodule update --init --force || exit 1

if [[ "$OSTYPE" == "msys" ]]; then
    bit=$(getconf LONG_BIT)
    if [ "$bit" == "64" ]; then
        make release-static-win64 -j$HOST_NCORES || exit 1
    else
        make release-static-win32 -j$HOST_NCORES || exit 1
    fi
elif [[ "$OSTYPE" == "cygwin" ]]; then
    echo "monero-project supports building on Windows only with MSYS"
    exit 1
else
    # OS is not windows
    MONERO_BUILD_DIR="build/release"
    test -d $MONERO_BUILD_DIR || mkdir -p $MONERO_BUILD_DIR
    (cd $MONERO_BUILD_DIR && \
     cmake -D STATIC=ON -D BUILD_64=ON -D CMAKE_BUILD_TYPE=Release \
           -D OPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR \
           -D USE_DEVICE_TREZOR=${USE_DEVICE_TREZOR} \
     ../.. && make -j$HOST_NCORES wallet) || exit 1
fi
cd ../../

# build libmonero-cpp shared library
mkdir -p build && 
cd build && 
cmake -D USE_DEVICE_TREZOR=${USE_DEVICE_TREZOR} $@ .. &&
cmake --build . && 
make -j$HOST_NCORES .
