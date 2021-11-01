#!/usr/bin/env bash

# initialize submodules recursively
git submodule update --init --force --recursive

# update townforge
cd ./external/townforge
git checkout cc
git pull --ff-only origin cc
cd ../../