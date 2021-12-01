#!/bin/bash

set -e

make

cd bin
./app
cd ..