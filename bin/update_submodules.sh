#!/usr/bin/env bash

# initialize submodules recursively
git submodule update --init --force --recursive

# update monero-project
cd ./external/monero-project
git checkout light-wallet-maintenance
git pull --ff-only origin light-wallet-maintenance
cd ../../