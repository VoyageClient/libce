#!/bin/sh

set -e

make clean
rm -f olm-*.tgz

make lib
make test
