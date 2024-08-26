#!/bin/bash
cd build && rm -f libmonero-cpp.dylib && ../../../external/monero-project/contrib/depends/x86_64-apple-darwin11/native/bin/x86_64-apple-darwin11-lipo -create -output libmonero-cpp.dylib ../../x86/build/libmonero-cpp.dylib ../../arm/build/libmonero-cpp.dylib 
