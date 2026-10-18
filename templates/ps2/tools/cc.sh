#!/usr/bin/env bash
# Compile one C file the way the original PS2 game was built: an EE GCC
# (Sony's Linux builds, or SN Systems' Windows builds under wibo) followed by
# GNU as for the R5900, or Metrowerks CodeWarrior (mwccps2.exe under wibo),
# which writes the object itself.
# Usage: tools/cc.sh in.c out.o   (or: tools/cc.sh in.c -o out.o)
# Settings come from the environment (dk, make) or else from config.mk:
# DK_GCC (an ee-gcc version, or mwcps2-<version>), DK_CFLAGS, DK_G.
set -euo pipefail
IN="$1"
if [ "${2:-}" = "-o" ]; then OUT="$3"; else OUT="$2"; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="${DK_TOOLCHAIN:?load the toolchain first: . ~/decomp/toolchain/env.sh}"
if [ -z "${DK_GCC:-}" ]; then
    eval "$(sed -n 's/^export \(DK_[A-Z]*\) := \(.*\)$/\1="\2"/p' "$ROOT/config.mk")"
fi
EE="$TC/ee-gcc/$DK_GCC"
PRE="$TC/ee-gcc/2.96"  # a Linux build, used only to preprocess
PRE_LIB="$(dirname "$(find "$PRE/lib" -name cpp0 | head -1)")"
G="${DK_G:-0}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# DK_EXTRA_INCLUDE (from dk try) shadows headers, e.g. a game.h without a guessed
# prototype of the function being tried.
CPP_FLAGS="${DK_EXTRA_INCLUDE:+-I$DK_EXTRA_INCLUDE} -I$ROOT/include -I$ROOT/src"
mkdir -p "$(dirname "$OUT")"
# Dependencies for make come from the system cpp. It is 64-bit, so Metrowerks
# builds also run inside sandboxes that ban 32-bit programs (Codex on Linux).
cpp -M -nostdinc $CPP_FLAGS "$IN" 2>/dev/null | sed "1s|^[^:]*:|$OUT:|" > "$TMP/deps" || true

if [[ "$DK_GCC" == mwcps2-* ]]; then
    # mwccgap swaps each INCLUDE_ASM line for its assembled function. It reads C
    # from stdin whenever stdin isn't a terminal, so stdin must be empty.
    IN_ABS="$(cd "$(dirname "$IN")" && pwd)/$(basename "$IN")"
    OUT_ABS="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
    MW="$TC/mwcps2/${DK_GCC#mwcps2-}/mwccps2.exe"
    [ -f "$MW" ] || MW="${MW%/*}/mwccmips.exe"  # 2.3 (1999) has the older name
    (cd "$ROOT" && python3 "$TC/src/mwccgap/mwccgap.py" "$IN_ABS" "$OUT_ABS" \
        --mwcc-path "$MW" --use-wibo --wibo-path "$(command -v wibo)" \
        --as-path "$(command -v mipsel-none-elf-as)" --as-march r5900 --as-mabi eabi --as-flags "-G$G" \
        --macro-inc-path include/mwccgap.inc \
        -nostdinc -stderr ${DK_EXTRA_INCLUDE:+"-I$DK_EXTRA_INCLUDE"} "-I$ROOT/include" "-I$ROOT/src" $DK_CFLAGS \
        < /dev/null)
    python3 "$ROOT/tools/pad_functions.py" "$OUT_ABS"
    # Switch tables: point them at the game's own tables in the data blob (see there).
    (cd "$ROOT" && python3 tools/jtbl_fix.py "$OUT_ABS")
    mv "$TMP/deps" "$OUT.d"
    exit 0
fi
"$PRE/bin/ee-gcc" -B"$PRE_LIB/" -E $CPP_FLAGS "$IN" -o "$TMP/in.i"
if [ -x "$EE/bin/ee-gcc" ]; then
    LIB="$(dirname "$(find "$EE/lib" -name cc1 | head -1)")"
    (cd "$TMP" && "$EE/bin/ee-gcc" -B"$LIB/" -S "-G$G" $DK_CFLAGS in.i -o out.s)
else
    (cd "$TMP" && wibo "$EE/bin/ee-gcc.exe" -S "-G$G" $DK_CFLAGS in.i -o out.s)
fi

mipsel-none-elf-as -EL "-G$G" -march=r5900 -mabi=eabi -no-pad-sections \
    -I "$ROOT" -I "$ROOT/include" -o "$OUT" "$TMP/out.s"
mv "$TMP/deps" "$OUT.d"
