#!/bin/bash

LIBDIR="lib"
LIBYAML_VERSION="yaml-0.1.7"
LIBYAML_HOME=${LIBYAML_VERSION}

cd ${LIBDIR}

# get libyaml 0.1.7
wget http://pyyaml.org/download/libyaml/${LIBYAML_VERSION}.tar.gz 

# build libyaml
pushd .
tar xzf ${LIBYAML_VERSION}.tar.gz && cd ${LIBYAML_HOME}
./configure && cmake ./ && make
cd ${PWD}/${DEPDIR}
popd
