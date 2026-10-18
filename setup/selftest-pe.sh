#!/usr/bin/env bash
# Toolchain self-test: rebuild the finished Parasite Eve decomp with the shared
# toolchain and check the retail SHA-1. Needs a checkout that holds the retail
# assets/USA/main.exe (SLUS_006.62).
# Usage: selftest-pe.sh [pe-repo] [retail-exe]
set -euo pipefail
TC="${DK_TOOLCHAIN:-$HOME/decomp/toolchain}"
SRC_REPO="${1:-$HOME/parasite-eve-decomp-build}"
EXE="${2:-$SRC_REPO/assets/USA/main.exe}"
WORK="$HOME/decomp/selftest/parasite-eve"
. "$TC/env.sh"

rm -rf "$WORK"
mkdir -p "$(dirname "$WORK")"
git clone -q "$SRC_REPO" "$WORK"
cd "$WORK"
mkdir -p assets/USA
cp "$EXE" assets/USA/main.exe
ln -s "$TC/gcc/2.7.2" tools/old-gcc
ln -s "$TC/gcc/2.8.1" tools/old-gcc-281
ln -s "$TC/gas/2.7" tools/gas-2.7
ln -s "$TC/gas/2.8.1" tools/gas-2.8.1
ln -s "$TC/src/maspsx" tools/maspsx
ln -s "$TC/venv" .venv
export PE_CPP="$TC/gcc/2.7.2/cpp"

start=$(date +%s)
make -j"$(nproc)" check > "$WORK/selftest.log" 2>&1 || { tail -25 "$WORK/selftest.log"; echo "SELFTEST FAILED"; exit 1; }
echo "objects built: $(find build -name '*.o' | wc -l)"
echo "time: $(( $(date +%s) - start ))s"
tail -1 "$WORK/selftest.log"
echo "SELFTEST PASSED"
