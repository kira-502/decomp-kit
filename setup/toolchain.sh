#!/usr/bin/env bash
# Shared PlayStation decomp toolchain: GNU binutils for mipsel, the original-era
# PSX GCC compilers, historical GNU as builds, splat, m2c, maspsx, asm-differ,
# decomp-permuter, objdiff and the PsyQ library signatures, plus coddog
# (duplicate finder), ccc (PS2 debug symbols), headless Ghidra with the
# Emotion Engine extension, Mizuchi (Claude matching pipeline) and read-only
# reference decomps in $DK_REF (default ~/decomp/ref).
# Installs into $DK_TOOLCHAIN (default ~/decomp/toolchain). Safe to re-run.
set -euo pipefail

TC="${DK_TOOLCHAIN:-$HOME/decomp/toolchain}"
REF="${DK_REF:-$HOME/decomp/ref}"
OLD_GCC_RELEASE=0.17
OLD_GCC_VERSIONS="2.5.7 2.6.0 2.6.3 2.7.2 2.7.2-cdk 2.8.0 2.8.1 2.91.66 2.95.2"
OBJDIFF_VERSION=v3.8.2
CODDOG_VERSION=0.6.3
CCC_VERSION=v2.1
GHIDRA_VERSION=12.1.4
GHIDRA_BUILD=20260921
EE_GHIDRA_VERSION=v2.1.38
EE_GHIDRA_BUILD=20261004
BINUTILS_VERSION=2.45
# A machine that already built Parasite Eve has binutils and the old GAS builds.
PE_REPO="${DK_PE_REPO:-$HOME/parasite-eve-decomp-build}"
PE_BINUTILS="${DK_PE_BINUTILS:-$HOME/pe-binutils-build/build}"

mkdir -p "$TC/bin" "$TC/gcc" "$TC/gas" "$TC/src"
say() { printf '== %s\n' "$*"; }
is_elf() { [ -f "$1" ] && [ "$(head -c 4 "$1" | od -An -c | tr -d ' ')" = '177ELF' ]; }

say "binutils (mipsel-none-elf)"
if [ ! -x "$TC/bin/mipsel-none-elf-as" ]; then
    if is_elf "$PE_BINUTILS/gas/as-new"; then
        cp "$PE_BINUTILS/gas/as-new" "$TC/bin/mipsel-none-elf-as"
        cp "$PE_BINUTILS/ld/ld-new" "$TC/bin/mipsel-none-elf-ld"
        cp "$PE_BINUTILS/binutils/nm-new" "$TC/bin/mipsel-none-elf-nm"
        cp "$PE_BINUTILS/binutils/strip-new" "$TC/bin/mipsel-none-elf-strip"
        for t in objcopy objdump readelf ar size; do
            cp "$PE_BINUTILS/binutils/$t" "$TC/bin/mipsel-none-elf-$t"
        done
    else
        work="$(mktemp -d)"
        curl -fsSL "https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILS_VERSION.tar.xz" | tar xJ -C "$work"
        mkdir "$work/build"
        (cd "$work/build" && "../binutils-$BINUTILS_VERSION/configure" --target=mipsel-none-elf \
            --prefix="$TC" --disable-nls --disable-werror --disable-gdb --disable-gdbserver \
            --disable-sim --disable-gprofng >/dev/null && make -j"$(nproc)" >/dev/null && make install >/dev/null)
        rm -rf "$work"
    fi
fi

say "compilers (decompals/old-gcc $OLD_GCC_RELEASE)"
for v in $OLD_GCC_VERSIONS; do
    [ -x "$TC/gcc/$v/cc1" ] && continue
    case "$v" in
        *-cdk) asset="gcc-$v.tar.gz" ;;
        *) asset="gcc-$v-psx.tar.gz" ;;
    esac
    mkdir -p "$TC/gcc/$v"
    curl -fsSL "https://github.com/decompals/old-gcc/releases/download/$OLD_GCC_RELEASE/$asset" | tar xz -C "$TC/gcc/$v"
done

say "PS2 compilers (decompme/compilers: EE GCC builds)"
EE_GCC_VERSIONS="2.9-990721 2.9-991111 2.9-991111a 2.9-991111-01 2.9-991111-01-dtls13010 2.95.2-273a 2.95.3-114 2.95.3-136 2.96 3.2-030210-beta2 3.2-030926 3.2-040921"
for v in $EE_GCC_VERSIONS; do
    [ -d "$TC/ee-gcc/$v/bin" ] && continue
    mkdir -p "$TC/ee-gcc/$v"
    base="https://github.com/decompme/compilers/releases/download/compilers/ee-gcc$v"
    if curl -fsSL "$base.tar.xz" -o "$TC/ee-gcc/$v.tar"; then :; else curl -fsSL "$base.tar.gz" -o "$TC/ee-gcc/$v.tar"; fi
    tar xf "$TC/ee-gcc/$v.tar" -C "$TC/ee-gcc/$v"
    rm -f "$TC/ee-gcc/$v.tar"
done

say "PS2 compilers (decompme/compilers: Metrowerks CodeWarrior)"
MWCPS2_VERSIONS="2.3.3-000906 2.4-001213 3.0-011126 3.0.1-020123 3.0.3-020716 3.0b38-030307 3.0b50-030527
3.0b52-030722 3.0.1b44-030325 3.0.1b51-030512 3.0.1b74-030811 3.0.1b75-030916 3.0.1b87-031208
3.0.1b95-040309 3.0.1b103-040528 3.0.1b119-040914 3.0.1b145-050209 3.0.1b151-050317
3.0.1b198-051011 3.0.1b205-051227 3.0.1b210-060308"
for v in $MWCPS2_VERSIONS; do
    [ -d "$TC/mwcps2/$v" ] && continue
    mkdir -p "$TC/mwcps2/$v"
    curl -fsSL "https://github.com/decompme/compilers/releases/download/compilers/mwcps2-$v.tar.gz" \
        | tar xz -C "$TC/mwcps2/$v"
done

# decomp.me's bundle adds 2.3 (Dec 1999, mwccmips.exe) and the 3.0b22 builds.
if [ ! -d "$TC/mwcps2/2.3-991202" ]; then
    work="$(mktemp -d)"
    curl -fsSL https://github.com/decompme/compilers/releases/download/compilers/ps2_compilers.tar.xz \
        | tar xJ -C "$work"
    for d in "$work"/mwcps2-*; do
        v="${d##*/mwcps2-}"
        [ -d "$TC/mwcps2/$v" ] || mv "$d" "$TC/mwcps2/$v"
    done
    rm -rf "$work"
fi

# The Linux EE GCC builds are 32-bit; the SN Systems ones are Windows .exe files
# that run under wibo, decomp.me's small Win32 loader.
if [ ! -e /lib/ld-linux.so.2 ]; then
    echo "32-bit libc missing: run  wsl.exe -d Ubuntu-24.04 -u root apt-get install -y libc6-i386"
fi
WIBO_VERSION=1.2.0
if [ ! -x "$TC/bin/wibo" ]; then
    curl -fsSL -o "$TC/bin/wibo" "https://github.com/decompals/wibo/releases/download/$WIBO_VERSION/wibo-x86_64"
    chmod +x "$TC/bin/wibo"
fi

say "historical GNU as (2.7, 2.8.1)"
for v in 2.7 2.8.1; do
    [ -x "$TC/gas/$v/as" ] && continue
    mkdir -p "$TC/gas/$v"
    if is_elf "$PE_REPO/tools/gas-$v/as"; then
        cp "$PE_REPO/tools/gas-$v/as" "$TC/gas/$v/as"
    else
        case "$v" in
            2.7) PE_GAS27_DIR="$TC/gas/$v" bash "$PE_REPO/tools/scripts/setup_gas27.sh" ;;
            2.8.1) PE_GAS281_DIR="$TC/gas/$v" bash "$PE_REPO/tools/scripts/setup_gas281.sh" ;;
        esac
    fi
done

say "python tools"
[ -x "$TC/venv/bin/python" ] || python3 -m venv "$TC/venv"
"$TC/venv/bin/pip" install -q --upgrade pip
# splat is pinned: a new version can change the split, so bump it only after a
# project still rebuilds byte-exact with it.
"$TC/venv/bin/pip" install -q "splat64[mips]==0.50.1" pycparser toml levenshtein cxxfilt colorama ansiwrap watchdog

say "git tools"
clone() { [ -d "$TC/src/$2/.git" ] || git clone -q --depth 1 "https://github.com/$1.git" "$TC/src/$2"; }
clone mkst/maspsx maspsx
clone matt-kempster/m2c m2c
clone simonlindholm/asm-differ asm-differ
clone simonlindholm/decomp-permuter decomp-permuter
clone lab313ru/psx_psyq_signatures psx_psyq_signatures
clone mkst/mwccgap mwccgap
# mwccgap indexes the function's rodata sections without checking there are
# any; a j/jal to a local label in a function without rodata crashes it.
sed -i 's/if relocation_record.sh_info == rodata_section_indices\[0\]:/if rodata_section_indices and relocation_record.sh_info == rodata_section_indices[0]:/' \
    "$TC/src/mwccgap/mwccgap/mwccgap.py"

say "objdiff-cli $OBJDIFF_VERSION"
if ! "$TC/bin/objdiff-cli" --version 2>/dev/null | grep -qF "${OBJDIFF_VERSION#v}"; then
    curl -fsSL -o "$TC/bin/objdiff-cli" \
        "https://github.com/encounter/objdiff/releases/download/$OBJDIFF_VERSION/objdiff-cli-linux-x86_64"
    chmod +x "$TC/bin/objdiff-cli"
fi

say "coddog $CODDOG_VERSION (duplicate and look-alike functions)"
if ! "$TC/bin/coddog" --version 2>/dev/null | grep -qF "$CODDOG_VERSION"; then
    work="$(mktemp -d)"
    curl -fsSL "https://github.com/ethteck/coddog/releases/download/$CODDOG_VERSION/coddog-cli-x86_64-unknown-linux-gnu.tar.xz" \
        | tar xJ -C "$work"
    install -m 755 "$(find "$work" -type f -name coddog | head -1)" "$TC/bin/coddog"
    rm -rf "$work"
fi

say "ccc $CCC_VERSION (PS2 debug symbols: stdump, uncc)"
if [ ! -x "$TC/bin/stdump" ]; then
    work="$(mktemp -d)"
    curl -fsSL -o "$work/ccc.zip" \
        "https://github.com/chaoticgd/ccc/releases/download/$CCC_VERSION/ccc_${CCC_VERSION}_linux-musl.zip"
    python3 -m zipfile -e "$work/ccc.zip" "$work/x"
    for b in stdump uncc; do install -m 755 "$(find "$work/x" -type f -name "$b" | head -1)" "$TC/bin/$b"; done
    rm -rf "$work"
fi

# Headless only: dk and agents call analyzeHeadless; nobody opens the GUI.
say "Ghidra $GHIDRA_VERSION + Emotion Engine extension $EE_GHIDRA_VERSION"
GHIDRA="$TC/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC"
if ! command -v java >/dev/null || ! command -v unzip >/dev/null; then
    echo "Java or unzip missing: run  wsl.exe -d Ubuntu-24.04 -u root apt-get install -y openjdk-21-jdk-headless unzip"
else
    if [ ! -x "$GHIDRA/support/analyzeHeadless" ]; then
        work="$(mktemp -d)"
        curl -fsSL -o "$work/ghidra.zip" \
            "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip"
        mkdir -p "$TC/ghidra"
        unzip -q "$work/ghidra.zip" -d "$TC/ghidra"
        rm -rf "$work"
    fi
    if [ ! -d "$GHIDRA/Ghidra/Extensions/ghidra-emotionengine-reloaded" ]; then
        work="$(mktemp -d)"
        curl -fsSL -o "$work/ee.zip" \
            "https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/download/$EE_GHIDRA_VERSION/ghidra_${GHIDRA_VERSION}_PUBLIC_${EE_GHIDRA_BUILD}_ghidra-emotionengine-reloaded.zip"
        unzip -q "$work/ee.zip" -d "$GHIDRA/Ghidra/Extensions"
        rm -rf "$work"
    fi
    ln -sf "$GHIDRA/support/analyzeHeadless" "$TC/bin/ghidra-headless"
fi

say "Mizuchi (Claude + m2c + objdiff matching pipeline)"
clone macabeus/mizuchi mizuchi
if command -v npm >/dev/null && [ ! -d "$TC/src/mizuchi/node_modules" ]; then
    (cd "$TC/src/mizuchi" && npm ci --no-audit --no-fund --loglevel=error && npm run -s build && npm run -s build:ui)
fi

# GPT helpers for dk grind: the Codex CLI runs inside Linux so its sandbox can
# confine each helper to the project (Windows' sandbox blocks wsl.exe).
say "Codex CLI for dk grind"
if command -v npm >/dev/null && [ ! -x "$TC/codex/bin/codex" ]; then
    npm install -g --prefix "$TC/codex" @openai/codex@0.162.1 --no-audit --no-fund --loglevel=error
fi
mkdir -p "$TC/codex-home" && chmod 700 "$TC/codex-home"
if [ ! -f "$TC/codex-home/config.toml" ]; then
    printf '%s\n' 'model = "gpt-6.1-sol"' 'model_reasoning_effort = "max"' '' '[sandbox_workspace_write]' \
        "writable_roots = [\"$HOME/.ghidra\", \"$HOME/.config/ghidra\"]" > "$TC/codex-home/config.toml"
fi
[ -f "$TC/codex-home/auth.json" ] ||
    echo "Codex login: copy Windows ~/.codex/auth.json to $TC/codex-home/auth.json (chmod 600)"

# Other matching decomps on the same compilers, kept to read, never built.
say "reference decomps (read-only) in $REF"
mkdir -p "$REF"
ref() { [ -d "$REF/$2/.git" ] || git clone -q --depth 1 "https://github.com/$1.git" "$REF/$2"; }
ref TheMoonPeople/Chronicle dark-cloud          # Dark Cloud: Metrowerks 2.3.3, 100% matched, overlays
ref FastestMolasses/Extermination extermination # Metrowerks 2.3.3 at -O4,p
ref veldrift/gt4-decomp gt4                     # Gran Turismo 4: Claude agents do the matching
ref DanielSant0s/ELF2MWO elf2mwo                # writes Metrowerks MWo3 overlays (the format DotR uses)

cat > "$TC/env.sh" <<EOF
export DK_TOOLCHAIN="$TC"
export PATH="$TC/bin:$TC/venv/bin:\$PATH"
EOF

say "installed"
"$TC/bin/mipsel-none-elf-as" --version | head -1
ls "$TC/gcc" | tr '\n' ' '; echo
ls "$TC/gas" | sed 's/^/gas /' | tr '\n' ' '; echo
"$TC/venv/bin/python" -c 'import splat, spimdisasm, rabbitizer; print("splat", splat.__version__, "| spimdisasm", spimdisasm.__version__, "| rabbitizer", rabbitizer.__version__)'
"$TC/bin/objdiff-cli" --version
"$TC/bin/coddog" --version
[ -x "$GHIDRA/support/analyzeHeadless" ] && echo "ghidra $GHIDRA_VERSION + emotionengine $EE_GHIDRA_VERSION"
for r in maspsx m2c asm-differ decomp-permuter psx_psyq_signatures mwccgap mizuchi; do
    printf '%s %s\n' "$r" "$(git -C "$TC/src/$r" log -1 --format='%h %ad' --date=short)"
done
du -sh "$TC" | cut -f1
