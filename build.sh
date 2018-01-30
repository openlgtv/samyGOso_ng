#!/bin/bash
scriptDir="$(readlink -f "$(dirname "$0")")"
[ ! -d "${scriptDir}/build" ] && mkdir -p "${scriptDir}/build"
cd "${scriptDir}/build"
cmake \
	-G "Unix Makefiles" \
	-DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_C_COMPILER=${CROSS_COMPILE}gcc \
	-DCMAKE_CXX_COMPILER=${CROSS_COMPILE}g++ \
	..
make "$@"
