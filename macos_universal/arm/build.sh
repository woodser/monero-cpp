#!/bin/bash
cd build && cmake -DCMAKE_TOOLCHAIN_FILE=../../../external/monero-project/contrib/depends/aarch64-apple-darwin11/share/toolchain.cmake .. && make
