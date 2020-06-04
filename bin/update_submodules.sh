#!/usr/bin/env bash

# initialize submodules recursively
git submodule update --init --recursive

# update monero-cpp
git checkout tags/v0.3.0
git pull --ff-only origin master

# update monero-core
cd ./external/monero-core
git checkout tags/v0.16.0.0
git pull --ff-only origin master
cd ../../