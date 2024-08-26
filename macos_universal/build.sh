#!/bin/bash
cd .. && ./bin/update_submodules.sh
cd external/monero-project && make depends target=x86_64-apple-darwin11
make depends target=aarch64-apple-darwin11

cd ../../macos_universal/universal && ./combine_and_build_all.sh
