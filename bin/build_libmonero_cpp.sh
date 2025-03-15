#!/bin/bash

CURRENT_ARCH=`uname -m`
CURRENT_OS=`uname -s`

cd ./external/monero-project/ || exit 1
git submodule update --init --force || exit 1
HOST_NCORES=$(nproc 2>/dev/null || shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
if [[ $CURRENT_OS == "MINGW64_NT"* || $CURRENT_OS == "MSYS"* ]]; then
    VERSION="${CURRENT_ARCH}-W${bit}-${CURRENT_OS}"

    # monero-project 
    if [ -z $SKIP_MP ]; then
        bit=$(getconf LONG_BIT)
        rm -rf build/release
        rm -rf ../../external-libs/$VERSION/monero-project/
        mkdir ../../external-libs/$VERSION/monero-project/
        if [ "$bit" == "64" ]; then
            make release-static-win64 -j$HOST_NCORES || exit 1
        else
            make release-static-win32 -j$HOST_NCORES || exit 1
        fi
        mv build/release ../../external-libs/$VERSION/monero-project/
    fi

    # monero-cpp
    cd ../../
    rm -rf build/$CURRENT_ARCH/release 
    mkdir -p build/$CURRENT_ARCH/release &&
    cd build/$CURRENT_ARCH/release &&
    cmake -DMON_VERSION=$VERSION ../../.. &&
    cmake --build . &&
    make -j$HOST_NCORES .

elif [ $CURRENT_OS == "Darwin" ]; then

    VERSION="${CURRENT_ARCH}-apple-darwin11"

    # Build current architecture only.
    # monero-project
    if [ -z $SKIP_MP ]; then
        printf "\nBuilding native release static version of monero-project for ${VERSION}\n"
        rm -rf build/release 
        make release-static -j$HOST_NCORES || exit 1
        rm -rf ../../external-libs/$VERSION/monero-project
        mkdir -p ../../external-libs/$VERSION/monero-project/ &&
        mv build/release ../../external-libs/$VERSION/monero-project/
    fi

    # monero-cpp
    cd ../..
    printf "\nBuilding native Monero-cpp for ${VERSION}\n"
    rm -rf build/$VERSION/release && 
    mkdir -p build/$VERSION/release && 
    cd build/$VERSION/release && 
    cmake -DSTATIC=$STATIC -D MON_VERSION=$VERSION ../../.. && 
    cmake --build . 

else
    # Running on Linux
    # "OS" will be used as if it is called "WRAPPER"

    rm -rf build
    BUILD_BOTH_ARCHS=0
    OS=""
    VENDOR=""

    if [ "${TARGET}" == "darwin" ]; then
        OS="darwin11"
        VENDOR="apple"
        if [ -z "${ARCH}" ]; then
            BUILD_BOTH_ARCHS=1
        fi
    elif [ "${TARGET}" == "MSYS" ] || [ "${TARGET}" == "MINGW64_NT" ]; then
        OS="mingw32"
        VENDOR="w64"
    else
        OS="gnu"
        VENDOR="linux"
    fi

    CPU=""
    if [ -n "${ARCH}" ]; then
        CPU="${ARCH}"
    else
        CPU=$CURRENT_ARCH 
    fi

    if [ $BUILD_BOTH_ARCHS == 1 ]; then
        # The target is darwin.
        printf "\nBuilding both Darwin architectures as a fat library\n"

        ARM64_TOOLCHAIN="contrib/depends/aarch64-apple-darwin11/share/toolchain.cmake"
        X86_64_TOOLCHAIN="contrib/depends/x86_64-apple-darwin11/share/toolchain.cmake"

        if [ -z $SKIP_MP ]; then
            printf "\nBuilding compilation dependencies for aarch64 Darwin\n"
            CUR_VERSION="aarch64-apple-darwin11" 
            cd contrib/depends &&
            rm -rf "${CUR_VERSION}"
            make HOST=$CUR_VERSION -j$HOST_NCORES &&
            echo \
            "set(FRAMEWORK_DIR \"contrib/depends/$CUR_VERSION/native/SDK/System/Library/Frameworks\")" \
            >> ../../$ARM64_TOOLCHAIN &&
            cd ../..

            # build monero-project
            printf "\nBuilding monero-project for aarch64 Darwin\n"
            rm -rf build &&
            mkdir -p build/release && cd build/release &&
            cmake -j$HOST_NCORES -D STATIC=ON -D CMAKE_BUILD_TYPE=Release -D CMAKE_TOOLCHAIN_FILE=../../$ARM64_TOOLCHAIN ../.. && make -j$HOST_NCORES &&
            rm -rf ../../../../external-libs/$CUR_VERSION/monero-project
            mkdir -p ../../../../external-libs/$CUR_VERSION/monero-project/ &&
            cd ../.. && mv build/release ../../external-libs/$CUR_VERSION/monero-project/
    
            # build monero-x64_64
            # Make dependencies
            printf "\nBuilding compilation dependencies for x86_64 Darwin\n"
            CUR_VERSION="x86_64-apple-darwin11" 
            cd contrib/depends &&
            rm -rf "${CUR_VERSION}"
            make HOST=$CUR_VERSION -j$HOST_NCORES &&
            echo \
            "set(FRAMEWORK_DIR \"contrib/depends/$CUR_VERSION/native/SDK/System/Library/Frameworks\")" \
            >> ../../$X86_64_TOOLCHAIN &&
            cd ../..

            # build monero-project
            printf "\nBuilding monero-project for x86_64 Darwin\n"
            rm -rf build/release && mkdir -p build/release && cd build/release &&
            cmake -j$HOST_NCORES -D STATIC=ON -D CMAKE_BUILD_TYPE=Release -D CMAKE_TOOLCHAIN_FILE=../../$X86_64_TOOLCHAIN ../.. &&
            make -j$HOST_NCORES &&
            rm -rf ../../../../external-libs/$CUR_VERSION/monero-project
            mkdir -p ../../../../external-libs/$CUR_VERSION/monero-project/
            cd ../.. && mv build/release ../../external-libs/$CUR_VERSION/monero-project/
        fi

        # Build monero-cpp x86_64
        printf "\nBuilding x86_64 monero-cpp for Darwin\n"
        cd ../../ &&
        rm -rf build/x86_64-apple-darwin11/release &&
        rm -rf build/aarch64-apple-darwin11/release &&
        rm -rf build/darwin &&
        mkdir -p build/x86_64-apple-darwin11/release &&
        mkdir -p build/aarch64-apple-darwin11/release &&
        mkdir -p build/darwin/release
        
        cd build/x86_64-apple-darwin11/release && 
        cmake -j$HOST_NCORES -D STATIC=$STATIC -D MON_VERSION=x86_64-apple-darwin11 -D CMAKE_TOOLCHAIN_FILE=../../../external/monero-project/$X86_64_TOOLCHAIN ../../.. &&
        make -j$HOST_NCORES
        
        # Build monero-cpp arm64
        printf "\nBuilding aarch64 monero-cpp for Darwin\n"
        cd ../../aarch64-apple-darwin11/release && 
        cmake -j$HOST_NCORES -D STATIC=$STATIC -D MON_VERSION=aarch64-apple-darwin11 -D CMAKE_TOOLCHAIN_FILE=../../../external/monero-project/$ARM64_TOOLCHAIN ../../.. &&
        make -j$HOST_NCORES
        
        # lipo the two builds together
        cd ../../..
        SUFFIX="dylib"
        if [ -n STATIC ]; then
            SUFFIX="a"
        fi
        ./external/monero-project/contrib/depends/${CURRENT_ARCH}-apple-darwin11/native/bin/${CURRENT_ARCH}-apple-darwin11-lipo -create -output build/darwin/release/libmonero-cpp.${SUFFIX} build/x86_64-apple-darwin11/release/libmonero-cpp.${SUFFIX} build/aarch64-apple-darwin11/release/libmonero-cpp.${SUFFIX}

    elif [ $CPU == $CURRENT_ARCH ] && [ $VENDOR == "linux" ]; then
        # Fast native build / No Depends

        VERSION="${CPU}-linux-gnu"
    
        # Build current architecture only.
        # monero-project
        printf "\nBuilding native release static version of monero-project for ${VERSION}\n"
        rm -rf build/release 
        make release-static USE_SINGLE_BUILDDIR=1 -j$HOST_NCORES || exit 1
        rm -rf ../../external-libs/$VERSION/monero-project
        mkdir -p ../../external-libs/$VERSION/monero-project/ &&
        mv build/release ../../external-libs/$VERSION/monero-project/
        cd ../..
    
        # monero-cpp
        printf "\nBuilding native Monero-cpp for ${VERSION}\n"
        rm -rf build/$VERSION/release && 
        mkdir -p build/$VERSION/release && 
        cd build/$VERSION/release && 
        cmake -D STATIC=$STATIC -D MON_VERSION=$VERSION ../../.. && 
        cmake --build . && 
        make -j$HOST_NCORES .

    else
        # Building 1 architecture for any platform

        # "OS" is used as if it is named "WRAPPER"
        VERSION="${CPU}-${VENDOR}-${OS}" && 
        printf "\nBuilding for ${VERSION}\n"

        # Make dependencies.
        if [ -z $SKIP_MP ]; then
            printf "\nBuilding compilation dependencies\n"
            cd contrib/depends &&
            rm -rf "${VERSION}"
            make HOST=$VERSION -j$HOST_NCORES &&
            if [ $OS == "darwin11" ]; then
                echo \
                "set(FRAMEWORK_DIR \"contrib/depends/$VERSION/native/SDK/System/Library/Frameworks\")" \
                >> $VERSION/share/toolchain.cmake
            fi
            cd ../..

            # Build monero-project
            printf "\nBuilding monero-project for ${VERSION}\n"
            rm -rf build/release && mkdir -p build/release && cd build/release &&
            cmake -j$HOST_NCORES -D STATIC=ON -D CMAKE_BUILD_TYPE=Release -D CMAKE_TOOLCHAIN_FILE=../../contrib/depends/$VERSION/share/toolchain.cmake ../.. &&
            make -j$HOST_NCORES &&
            rm -rf ../../../../external-libs/$VERSION/monero-project
            mkdir -p ../../../../external-libs/$VERSION/monero-project/ &&
            cd ../.. && mv build/release ../../external-libs/$VERSION/monero-project/
        fi

        # Build monero-cpp
        printf "\nBuilding monero-cpp for ${VERSION}\n"
        rm -rf ../../build/$VERSION/release &&
        mkdir -p ../../build/$VERSION/release && 
        cd ../../build/$VERSION/release &&
        cmake -j$HOST_NCORES -D STATIC=$STATIC -D MON_VERSION=$VERSION -D CMAKE_TOOLCHAIN_FILE=../../../external/monero-project/contrib/depends/$VERSION/share/toolchain.cmake ../../.. && 
        make -j$HOST_NCORES
    fi 
fi

