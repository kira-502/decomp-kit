#!/usr/bin/env bash
# Compile one C file the way the original game was built:
# original-era GCC (cpp + cc1) -> maspsx -> GNU as.
# Usage: tools/cc.sh in.c out.o   (or: tools/cc.sh in.c -o out.o)
# Settings come from the environment (dk, make) or else from config.mk:
# DK_GCC, DK_CFLAGS, DK_G, DK_MASPSX.
set -euo pipefail
IN="$1"
if [ "${2:-}" = "-o" ]; then OUT="$3"; else OUT="$2"; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="${DK_TOOLCHAIN:?load the toolchain first: . ~/decomp/toolchain/env.sh}"
if [ -z "${DK_GCC:-}" ]; then
    eval "$(sed -n 's/^export \(DK_[A-Z]*\) := \(.*\)$/\1="\2"/p' "$ROOT/config.mk")"
fi
GCC_DIR="$TC/gcc/$DK_GCC"
G="${DK_G:-0}"
AS="$(command -v mipsel-none-elf-as)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CPP_FLAGS="-undef -D__GNUC__=2 -D__OPTIMIZE__ -Dmips -D__mips__ -D__mips -D__LITTLE_ENDIAN__"
# DK_EXTRA_INCLUDE (from dk try) shadows headers, e.g. a game.h without a guessed
# prototype of the function being tried.
CPP_FLAGS="$CPP_FLAGS -D_LANGUAGE_C -DLANGUAGE_C ${DK_EXTRA_INCLUDE:+-I$DK_EXTRA_INCLUDE} -I$ROOT/include -I$ROOT/src"
mkdir -p "$(dirname "$OUT")"
"$GCC_DIR/cpp" $CPP_FLAGS -M "$IN" 2>/dev/null | sed "1s|^[^:]*:|$OUT:|" > "$TMP/deps" || true
"$GCC_DIR/cpp" $CPP_FLAGS "$IN" -o "$TMP/in.i"
"$GCC_DIR/cc1" -quiet "-G$G" $DK_CFLAGS "$TMP/in.i" -o "$TMP/out.s"

EXTRA=()
if [ "$G" != 0 ]; then EXTRA+=(--dont-force-G0); fi
python3 "$TC/src/maspsx/maspsx.py" $DK_MASPSX ${EXTRA[@]+"${EXTRA[@]}"} \
    --gnu-as-path="$AS" --run-assembler \
    -EL "-G$G" -march=r3000 -mtune=r3000 -no-pad-sections \
    -I "$ROOT" -I "$ROOT/include" -o "$OUT" < "$TMP/out.s"
mv "$TMP/deps" "$OUT.d"
