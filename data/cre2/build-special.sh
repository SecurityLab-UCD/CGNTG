#!/usr/bin/env bash

# CRE2 library does not use the pipeline of the other libraries with a different
# layout due to technical difficulties.
#
# Build CRE2 into the exact layout expected by
# src/execution/sanitize.rs::validate_cre2_program, i.e.:
#   include dir: /opt/re2/2024-07-02/shared/include
#   lib dir:     /opt/re2/2024-07-02/shared/lib64
# This script installs headers and a libcre2.so at the paths expected by the
# sanitizer.
#
# Usage:
#   bash data/cre2/build-special.sh
#
# Optional env vars:
#   DEST_PREFIX   (default: /opt/re2/2024-07-02/shared)
#   JOBS          (default: nproc)
#
set -euo pipefail
set -x

DEST_PREFIX=${DEST_PREFIX:-/opt/re2/2024-07-02/shared}
JOBS=${JOBS:-$(nproc)}

INCLUDE_DIR="${DEST_PREFIX}/include"
LIB_DIR="${DEST_PREFIX}/lib64"

# Working directories
ROOT_DIR=$(pwd)
BUILD_ROOT="${ROOT_DIR}/_build"
SRC_DIR="${BUILD_ROOT}/src"
INSTALL_DIR="${BUILD_ROOT}/install"

rm -rf "${SRC_DIR}" "${INSTALL_DIR}" "${INCLUDE_DIR}" "${LIB_DIR}"
mkdir -p "${SRC_DIR}" "${INSTALL_DIR}" "${INCLUDE_DIR}" "${LIB_DIR}"

echo
echo "Installing build dependencies..."
apt-get update || true
apt-get install -y --no-install-recommends \
  build-essential git autoconf automake libtool pkg-config file cmake \
  libre2-dev libabsl-dev || true

echo
echo "Building CRE2"
pushd "${SRC_DIR}"

# Clone cre2 only (we use system RE2/Abseil via libre2-dev and libabsl-dev)
if [ ! -d cre2 ]; then
  git clone --depth 1 https://github.com/PromptFuzz/cre2
fi

# Build cre2 via autotools
pushd cre2
./autogen.sh
rm -rf build && mkdir -p build && pushd build
../configure --enable-maintainer-mode
make -j"${JOBS}"
make install prefix="${INSTALL_DIR}"
popd
popd

echo
echo "Installing..."

# Install header and library to expected prefix
INSTALL_LIB_DIR="${INSTALL_DIR}/lib"
if [ ! -f "${INSTALL_LIB_DIR}/libcre2.so" ]; then
  # Some environments may place it under lib64
  INSTALL_LIB_DIR="${INSTALL_DIR}/lib64"
fi

cp -f "${INSTALL_DIR}/include/cre2.h" "${INCLUDE_DIR}/cre2.h"
cp -f "${INSTALL_LIB_DIR}/libcre2.so" "${LIB_DIR}/libcre2.so"
cp -f "${INSTALL_LIB_DIR}/libcre2.so.0" "${LIB_DIR}/libcre2.so.0"

echo "CRE2 installed to: ${DEST_PREFIX}"
echo "- Headers: ${INCLUDE_DIR}"
echo "- Library: ${LIB_DIR}/libcre2.so ${LIB_DIR}/libcre2.so.0"
