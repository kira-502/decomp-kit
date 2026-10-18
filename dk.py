#!/usr/bin/env python3
"""decomp-kit (dk): matching-decompilation helpers for PlayStation 1 games.

  dk new NAME DISC        start a project from a disc image (.cue/.bin/.iso)
  dk build                rebuild and prove it still matches the original
  dk progress             how much is decompiled
  dk next [-n N]          easiest functions still in assembly
  dk draft FUNC           m2c first draft into work/FUNC.c
  dk try FUNC [FILE]      compile a draft and compare it with the original
  dk accept FUNC [FILE]   move matching C into src/, rebuild, commit
  dk perm FUNC [FILE]     let decomp-permuter search for the last few differences
  dk harvest [-n N]       accept every function m2c already matches, no edits
  dk revert FUNC          put a decompiled function back to its original asm
  dk libs                 name Sony PsyQ library functions from signatures
  dk compiler [-n N]      find the compiler version and flags that match

Project commands run inside ~/decomp/games/<game>.
"""
from __future__ import annotations

import argparse
import bisect
import difflib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

KIT = Path(__file__).resolve().parent
sys.path.insert(0, str(KIT))
from dklib.disc import Disc, PsxExe  # noqa: E402

import rabbitizer  # noqa: E402

TC = Path(os.environ.get("DK_TOOLCHAIN", Path.home() / "decomp/toolchain"))
GAMES = Path(os.environ.get("DK_GAMES", Path.home() / "decomp/games"))
R3000 = rabbitizer.InstrCategory.R3000GTE
CORES = str(os.cpu_count() or 4)
DEFAULTS = {
    "gcc": "2.7.2",
    "cflags": "-O2 -mips1 -mcpu=3000 -funsigned-char -w",
    "g": 0,
    "maspsx": "--aspsx-version=2.56",
}
INCLUDE_RE = re.compile(r'^INCLUDE_ASM\("([^"]+)",\s*(\w+)\);[ \t]*$', re.M)
INSN_RE = re.compile(r"^\s*/\* [0-9A-F]+ [0-9A-F]{8} ([0-9A-F]{8}) \*/\s+(?!\.)", re.M)  # not .word data
IDA_LOCAL_RE = re.compile(
    r"^(loc|locret|def|jpt|off|byte|word|dword|unk|asc|stru|flt|dbl|text|data|rdata|sdata|bss|sbss)_[0-9A-Fa-f]+$")


def die(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def run(cmd, cwd=None, env=None, check=True):
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    if check and p.returncode:
        die(f"failed: {' '.join(map(str, cmd))}\n{(p.stdout + p.stderr)[-3000:]}")
    return p


class Project:
    def __init__(self, root: Path, cfg: dict | None = None):
        self.root = root
        self.cfg = cfg if cfg is not None else json.loads((root / "dk.json").read_text())

    @classmethod
    def find(cls) -> "Project":
        here = Path.cwd().resolve()
        for d in (here, *here.parents):
            if (d / "dk.json").exists():
                return cls(d)
        die("not inside a dk project (no dk.json); cd into ~/decomp/games/<game> first")

    @property
    def ps2(self) -> bool:
        return self.cfg.get("platform") == "ps2"

    def as_flags(self, g: int | None = None) -> list[str]:
        g = self.cfg["g"] if g is None else g
        cpu = ["-march=r5900", "-mabi=eabi"] if self.ps2 else ["-march=r3000", "-mtune=r3000"]
        return ["-EL", f"-G{g}", *cpu, "-no-pad-sections"]

    def save(self):
        c = self.cfg
        (self.root / "dk.json").write_text(json.dumps(c, indent=2) + "\n")
        (self.root / "config.mk").write_text(
            "# Written by dk from dk.json; change dk.json, not this file.\n"
            f"EXE := {c['exe']}\nTARGET_SHA := {c['sha1']}\n"
            f"AS_FLAGS := {' '.join(self.as_flags(0))}\n"
            f"export DK_PLATFORM := {c.get('platform', 'psx')}\n"
            f"export DK_GCC := {c['gcc']}\nexport DK_CFLAGS := {c['cflags']}\n"
            f"export DK_G := {c['g']}\nexport DK_MASPSX := {c['maspsx']}\n")
        # coddog labels a function decompiled unless it has a .s file under `asm`.
        # A split files decompiled functions under matchings/ and dk accept moves
        # them there, so nonmatchings/ holds exactly the functions still in asm.
        (self.root / "decomp.yaml").write_text(
            "# Written by dk from dk.json, for tools that read decomp.yaml (coddog).\n"
            f"name: {c['name']}\nplatform: {c.get('platform', 'psx')}\nversions:\n"
            f"- name: main\n  fullname: {c['exe']}\n  sha1: {c['sha1']}\n  paths:\n"
            f"    target: assets/{c['exe']}\n    build_dir: build\n    map: build/main.map\n"
            f"    compiled_target: build/{c['exe']}\n    elf: build/main.elf\n"
            "    asm: asm/nonmatchings\n")

    def env(self, **over) -> dict:
        c = {**self.cfg, **{k: v for k, v in over.items() if v is not None}}
        e = dict(os.environ)
        e.update(DK_PLATFORM=c.get("platform", "psx"), DK_GCC=c["gcc"], DK_CFLAGS=c["cflags"],
                 DK_G=str(c["g"]), DK_MASPSX=c["maspsx"])
        return e

    def category(self):
        return rabbitizer.InstrCategory.R5900 if self.ps2 else R3000

    def cpp(self) -> list:
        """Preprocessor command prefix (output to -o FILE, no line markers)."""
        if self.ps2:
            # The system cpp: 64-bit, so drafts also work in sandboxes that ban 32-bit programs.
            return ["cpp", "-nostdinc", "-undef", "-D__GNUC__=2", "-P"]
        return [TC / "gcc" / self.cfg["gcc"] / "cpp", "-undef", "-D__GNUC__=2", "-P"]

    def make(self, *targets):
        return run(["make", "-j", CORES, *targets], cwd=self.root, env=self.env(), check=False)

    def func_asm(self, func: str) -> Path:
        hit = getattr(self, "_asm", {}).get(func)
        if hit is None or not hit.exists():
            # One walk of asm/ serves every lookup; a walk per function made dk progress slow.
            self._asm: dict[str, Path] = {}
            for f in sorted(self.root.glob("asm/**/nonmatchings/**/*.s")):
                self._asm.setdefault(f.stem, f)
            hit = self._asm.get(func)
        if hit is None:
            die(f"{func}: no asm/nonmatchings file (wrong name, or already decompiled)")
        return hit

    def c_files(self) -> list[Path]:
        """src/*.c, without the temporary copies mwccgap writes beside them while
        another process is building."""
        return sorted(f for f in (self.root / "src").rglob("*.c") if not f.name.startswith("tmp"))

    def remaining(self) -> dict[str, Path]:
        out = {}
        for f in self.c_files():
            for m in INCLUDE_RE.finditer(f.read_text()):
                out[m.group(2)] = f
        return out


# ---------------------------------------------------------------- layout

POINTER_LO, POINTER_HI = 0x80000000, 0x80200000
LS_OPS = {0x09, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x28, 0x29, 0x2A, 0x2B, 0x2E}


@dataclass
class Image:
    """The loadable part of a PS1 EXE or a PS2 ELF."""
    platform: str
    data: bytes
    offset: int    # file offset of the loaded bytes
    base: int      # their address in RAM
    size: int
    bss: int
    entry: int
    gp: int
    overlays: list[tuple[int, int]]  # (address, size) of code loaded later (PS2 ELF placeholders)

    def words(self) -> list[int]:
        body = self.data[self.offset:self.offset + self.size]
        return list(struct.unpack_from(f"<{len(body) // 4}I", body))

    @property
    def category(self):
        return rabbitizer.InstrCategory.R5900 if self.platform == "ps2" else R3000


def load_image(data: bytes) -> Image:
    if data[:4] != b"\x7fELF":
        h = PsxExe.parse(data)
        return Image("psx", data, 0x800, h.t_addr, h.t_size, h.b_size, h.pc0, h.gp0, [])
    entry, phoff = struct.unpack_from("<II", data, 0x18)
    phsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    loads = []
    for i in range(phnum):
        p_type, off, vaddr, _, filesz, memsz = struct.unpack_from("<6I", data, phoff + i * phsize)
        if p_type == 1:
            loads.append((off, vaddr, filesz, memsz))
    off, vaddr, filesz, memsz = max(loads, key=lambda s: s[2])
    img = Image("ps2", data, off, vaddr, filesz, memsz - filesz, entry, 0,
                [(v, m) for _, v, f, m in loads if f == 0 and m])
    img.gp = find_gp(img)
    return img


def find_gp(img: Image) -> int:
    """$gp as the startup code sets it (lui $gp, hi / addiu|ori $gp, $gp, lo)."""
    words = img.words()
    start = (img.entry - img.base) // 4
    hi = None
    for w in words[start:start + 128]:
        if w >> 16 == 0x3C1C:
            hi = w & 0xFFFF
        elif hi is not None and w >> 16 in (0x279C, 0x379C):
            lo = w & 0xFFFF
            if w >> 16 == 0x279C and lo & 0x8000:
                lo -= 0x10000
            return ((hi << 16) + lo) & 0xFFFFFFFF
    return 0


def guess_layout(img: Image) -> tuple[int, int]:
    """Guess where code starts and ends inside the image. PsyQ links rodata,
    code, data (or code, rodata, data); PS2 links code first. Data words that
    look like PS1 RAM pointers are a strong 'not code' sign; on PS2 only the
    instruction decoder helps."""
    base, words = img.base, img.words()
    n = len(words)
    valid = [rabbitizer.Instruction(w, base + 4 * i, category=img.category).isValid()
             for i, w in enumerate(words)]
    pointer = [img.platform == "psx" and POINTER_LO <= w < POINTER_HI for w in words]

    def codeish(i):
        lo, hi = max(0, i - 4), min(n, i + 5)
        return all(valid[lo:hi]) and not any(pointer[lo:hi])

    starts = {img.entry}
    for i, w in enumerate(words):
        if w >> 26 == 3 and codeish(i):
            t = (base & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
            if base <= t < base + 4 * n:
                starts.add(t)
    lo, hi = min(starts), max(starts)
    if img.platform == "ps2":
        lo = base  # the ELF's loaded block starts with code
    i, last_ret = (hi - base) // 4, None
    while i < n and valid[i] and not pointer[i]:
        if words[i] == 0x03E00008:  # jr $ra
            last_ret = i
        i += 1
    end = last_ret + 2 if last_ret is not None else i
    return lo, base + 4 * end


def count_gp(img: Image, lo: int, hi: int) -> int:
    words = img.words()[(lo - img.base) // 4:(hi - img.base) // 4]
    return sum(1 for w in words if (w >> 26) in LS_OPS and (w >> 21) & 31 == 28)


# ---------------------------------------------------------------- PsyQ signatures

def _sig_matches(body: bytes, toks: list[str]) -> list[int]:
    fixed = [None if t == "??" else int(t, 16) for t in toks]
    best_s = best_l = 0
    s = None
    for i, v in enumerate(fixed + [None]):
        if v is not None and s is None:
            s = i
        elif v is None and s is not None:
            if i - s > best_l:
                best_s, best_l = s, i - s
            s = None
    if best_l < 8:
        return []
    anchor = bytes(fixed[best_s:best_s + best_l])
    out, pos = [], body.find(anchor)
    while pos != -1:
        start = pos - best_s
        if start >= 0 and start % 4 == 0 and start + len(fixed) <= len(body) and all(
                f is None or body[start + k] == f for k, f in enumerate(fixed)):
            out.append(start)
        pos = body.find(anchor, pos + 1)
    return out


def scan_psyq(img: Image, lo: int, hi: int):
    """Find Sony PsyQ library objects in the code. Returns (best SDK version,
    {address: function name}, matched object count)."""
    body = img.data[img.offset + lo - img.base:img.offset + hi - img.base]
    root = TC / "src/psx_psyq_signatures"
    cache: dict[str, list[int]] = {}
    per_version: dict[str, list] = {}
    for vdir in sorted(p for p in root.iterdir() if p.name.isdigit()):
        hits = []
        for jf in sorted(vdir.glob("*.json")):
            for obj in json.loads(jf.read_text()):
                if "sig" not in obj:  # bss-only objects have no code
                    continue
                toks = obj["sig"].split()
                if len(toks) < 24:
                    continue
                if obj["sig"] not in cache:
                    cache[obj["sig"]] = _sig_matches(body, toks)
                for off in cache[obj["sig"]]:
                    hits.append((off, len(toks), obj["labels"]))
        per_version[vdir.name] = hits
    best = max(per_version, key=lambda v: sum(h[1] for h in per_version[v]))
    names: dict[int, str] = {}
    for v in [best] + [v for v in per_version if v != best]:
        for off, _, labels in per_version[v]:
            for lab in labels:
                if not IDA_LOCAL_RE.match(lab["name"]):  # branch targets, not functions
                    names.setdefault(lo + off + lab["offset"], lab["name"])
    uses = Counter(names.values())
    names = {a: n for a, n in names.items() if uses[n] == 1}
    return best, names, len({h[0] for h in per_version[best]})


def write_symbols(p: Project, names: dict[int, str]):
    lines = [f"{n} = 0x{a:08X}; // type:func\n" for a, n in sorted(names.items())]
    (p.root / "config/symbol_addrs.txt").write_text("".join(lines))


# ---------------------------------------------------------------- splat config

SPLAT_YAML = """\
name: {name} ({exe})
sha1: {sha1}
options:
  basename: main
  target_path: assets/{exe}
  base_path: ..
  platform: {platform}
  compiler: {compiler}

  asm_path: asm
  src_path: src
  build_path: build
  ld_script_path: linker/main.ld

  migrate_rodata_to_functions: False
  find_file_boundaries: True
  # Without this, re-splitting next to an existing src/main.c skips some functions.
  disassemble_all: True
{gp}
  o_as_suffix: False
  use_legacy_include_asm: False

  asm_function_macro: glabel
  asm_jtbl_label_macro: jlabel
  asm_data_macro: dlabel
  generate_asm_macros_files: True

  section_order: [{order}]

  symbol_addrs_path:
    - config/symbol_addrs.txt
  undefined_funcs_auto_path: linker/undefined_funcs_auto.txt
  undefined_syms_auto_path: linker/undefined_syms_auto.txt

  subalign: {subalign}
  string_encoding: ASCII
  data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2
  ld_bss_is_noload: True

segments:
  - name: {head}
    type: {head_type}
    start: 0x0

  - name: main
    type: code
    start: 0x{start:X}
    vram: 0x{vram:08X}
    align: 4
    subalign: {subalign}
    bss_size: 0x{bss:X}
    subsegments:
{subs}
{tail}  - [0x{end:X}]
"""


def write_splat(p: Project):
    """Rodata that belongs to the code (strings, switch tables) is attributed
    to main.c once its bounds are known (cfg["rodata"]), so each function
    carries its own rodata and can be decompiled with it. A PS2 ELF is
    rebuilt whole: its headers before and after the loaded block are kept
    as binary blobs."""
    c = p.cfg
    start = c.get("offset", 0x800)
    off = lambda a: a - c["vram"] + start  # noqa: E731
    end = start + c["size"]
    ro = c.get("rodata")
    subs = []
    if c["text_start"] > c["vram"]:
        subs.append(f"      - [0x{start:X}, {'.rodata, main' if ro else 'rodata, rodata'}]")
    if c.get("chunks"):
        subs += [f"      - [0x{off(a):X}, {kind}, {name}]" for a, kind, name in c["chunks"]]
    else:
        subs.append(f"      - [0x{off(c['text_start']):X}, c, main]")
    data_at = c["data_start"]
    if ro and ro[0] >= c["data_start"]:
        subs.append(f"      - [0x{off(ro[0]):X}, .rodata, main]")
        data_at = ro[1]
    if off(data_at) < end:
        subs.append(f"      - [0x{off(data_at):X}, data, data]")
    gp = f"  gp_value: 0x{c['gp']:08X}\n" if c["gp"] else ""
    if p.ps2:
        order = '".text", ".data", ".rodata", ".sdata", ".sbss", ".bss"'
        tail = f"  - name: elf_tail\n    type: bin\n    start: 0x{end:X}\n\n" if c["file_size"] > end else ""
        end = c["file_size"]
    else:
        text_first = ro and ro[0] >= c["data_start"]
        order = ('".text", ".rodata"' if text_first else '".rodata", ".text"') + ', ".data", ".sdata", ".sbss", ".bss"'
        tail = ""
    yaml = SPLAT_YAML.format(
        name=c["name"], exe=c["exe"], sha1=c["sha1"], gp=gp, vram=c["vram"], subs="\n".join(subs),
        end=end, order=order, start=start, bss=c.get("bss", 0), tail=tail,
        platform="ps2" if p.ps2 else "psx", compiler="EEGCC" if p.ps2 else "GCC", subalign=4,
        head="elf_header" if p.ps2 else "header", head_type="bin" if p.ps2 else "header")
    if ro:
        yaml = yaml.replace("migrate_rodata_to_functions: False", "migrate_rodata_to_functions: True")
    (p.root / "config/main.yaml").write_text(yaml)


DATA_SYM_RE = re.compile(r"^dlabel (\w+)\n\s*/\* [0-9A-F]+ ([0-9A-F]{8})[^*]*\*/ (\.\w+)", re.M)


def find_rodata(p: Project) -> tuple[int, int] | None:
    """Bounds of the code's rodata. PsyQ links it either before the code or
    right after it; after it, it runs to the end of the last switch table plus
    any strings that follow."""
    c = p.cfg
    if c["text_start"] > c["vram"]:
        return c["vram"], c["text_start"]
    data = p.root / "asm/data/data.data.s"
    if not data.exists():
        return None
    syms = [(int(m.group(2), 16), m.group(1), m.group(3) == ".asciz")
            for m in DATA_SYM_RE.finditer(data.read_text())]
    tables = [i for i, s in enumerate(syms) if s[1].startswith("jtbl_")]
    if not tables:
        return None
    i = tables[-1] + 1
    while i < len(syms) and syms[i][2]:
        i += 1
    return c["data_start"], syms[i][0] if i < len(syms) else c["vram"] + c["size"]


# ---------------------------------------------------------------- asm facts

def asm_info(path: Path, lib_by_name: bool = True) -> tuple[int, list[str]]:
    """Instruction count and tags. A function splat did not name func_<address> is Sony
    library code (named by symbol_addrs) unless the project's own functions carry real
    names (dk.json "lib_by_name": false)."""
    text = path.read_text()
    tags = []
    if lib_by_name and not path.stem.startswith("func_"):
        tags.append("lib")
    if "Handwritten function" in text:
        tags.append("handwritten")
    calls = len(re.findall(r"\bjal\s", text))
    if calls:
        tags.append(f"calls:{calls}")
    if "jtbl_" in text:
        tags.append("switch")
    if re.search(r"%(?:hi|lo|gp_rel)\((?:D_|jtbl_|\.L)", text):
        tags.append("data")
    if VU0_RE.search(text):
        tags.append("vu0")
    return len(INSN_RE.findall(text.split("endlabel")[0])), tags  # not the padding after it


VU0_RE = re.compile(r"\$v[fi]\d|\bvcallms")  # PS2 vector unit 0 registers and microprogram calls


def skip_tags(p: Project) -> set[str]:
    """Function kinds dk skips by default: Sony library code, hand-written and
    vector-unit asm, code patched in after the build (never plain C), and switch
    tables until the project's rodata is attached. A Metrowerks PS2 project with
    tools/jtbl_fix.py points its switch tables at the game's own instead."""
    tables = p.cfg.get("rodata") or (str(p.cfg.get("gcc", "")).startswith("mwcps2")
                                     and (p.root / "tools/jtbl_fix.py").exists())
    return {"lib", "handwritten", "vu0", "patched"} | (set() if tables else {"switch"})


STYLE_RE = re.compile(r"/\* [0-9A-F]+ ([0-9A-F]{8}) [0-9A-F]{8} \*/\s+(\w+)\s+([^\n]*)")


def gcc_ranges(p: Project, min_run: int = 50) -> list[list[int]]:
    """PS2 code ranges built with GCC rather than the game's Metrowerks: GCC
    moves registers with daddu and saves them with sd/ld, Metrowerks uses
    paddub and sq/lq. A long GCC run is normally Sony's SDK libraries."""
    rows = []
    for f in (p.root / "asm").glob("**/nonmatchings/**/*.s"):
        mw = gcc = 0
        start = None
        for m in STYLE_RE.finditer(f.read_text()):
            start = int(m.group(1), 16) if start is None else start
            op, args = m.group(2), m.group(3).rstrip()
            if op == "paddub" and args.endswith("$zero") or op in ("sq", "lq") and "($sp)" in args:
                mw += 1
            elif op == "daddu" and args.endswith("$zero") or op in ("sd", "ld") and "($sp)" in args:
                gcc += 1
        if start is not None and mw != gcc:
            rows.append((start, mw < gcc))
    runs: list[list] = []
    for start, is_gcc in sorted(rows):
        if runs and runs[-1][2] == is_gcc:
            runs[-1][1] = start
            runs[-1][3] += 1
        else:
            runs.append([start, start, is_gcc, 1])
    return [[a, b] for a, b, is_gcc, n in runs if is_gcc and n >= min_run]


def tags_for(p: Project, func: str) -> tuple[int, list[str]]:
    """asm_info plus project knowledge (PS2 SDK ranges count as library code, unless
    config/gcc_files.txt gives the function's file its own GCC: then it is workable)."""
    path = p.func_asm(func)
    n, tags = asm_info(path, p.cfg.get("lib_by_name", True))
    if (p.cfg.get("gcc_ranges") and "lib" not in tags
            and f"src/{path.parent.name}.c" not in gcc_files(p)):
        m = INSN_RE.search(path.read_text())
        addr = int(m.group(0).split()[2], 16) if m else 0
        if any(a <= addr <= b for a, b in p.cfg["gcc_ranges"]):
            tags.append("lib")
    if func in patch_pieces(p):
        tags.append("patched")
    return n, tags


SAVED_REGS = frozenset(range(16, 24)) | {30}  # s0-s7, fp
RETURN_REGS = frozenset({2, 3})               # v0, v1
REG_NAMES = {2: "v0", 3: "v1", 30: "fp", **{r: f"s{r - 16}" for r in range(16, 24)}}
_PIECES: dict[Path, dict[str, str]] = {}


def piece_reason(words: list[tuple[int, int]], cat) -> str | None:
    """Why this code can only run as part of another function, or None. A
    compiled function saves s0-s7/fp before touching them, sets v0/v1 before
    reading them, and frees only the stack frame it made."""
    ins = [rabbitizer.Instruction(w, v, cat) for v, w in words]
    targets = {x.getBranchVramGeneric() for x in ins if x.isBranch()}
    sp: list[int] = []
    saved: set[int] = set()
    touched: set[int] = set()
    early: set[int] = set()    # v0/v1 read before set, in the straight run from the entry
    written: set[int] = set()
    straight, ret, last = True, False, None
    for i, x in enumerate(ins):
        op = x.getOpcodeName()
        if i and words[i][0] in targets:
            straight = False
        ret |= x.isJrRa()
        if op in ("addiu", "daddiu") and x.rs.value == x.rt.value == 29:
            sp.append(x.getProcessedImmediate())
        if x.hasDelaySlot():
            last = op
        slot = op in ("sq", "sd", "sw", "lq", "ld", "lw") and x.rs.value == 29 and x.rt.value in SAVED_REGS
        if slot and op[0] == "s":
            saved.add(x.rt.value)
        regs = [(True, getattr(x, f).value) for r, f in ((x.readsRs, "rs"), (x.readsRt, "rt"), (x.readsRd, "rd")) if r()]
        regs += [(False, getattr(x, f).value)
                 for m, f in ((x.modifiesRs, "rs"), (x.modifiesRt, "rt"), (x.modifiesRd, "rd")) if m()]
        for reads, reg in regs:
            if reg in SAVED_REGS and not slot:
                touched.add(reg)
            if straight and reads and reg in RETURN_REGS and reg not in written:
                early.add(reg)
        if straight:
            written |= {reg for reads, reg in regs if not reads}
            if x.isFunctionCall() or op == "syscall":
                written |= RETURN_REGS
        if i and ins[i - 1].hasDelaySlot():
            straight = False
    if sp and sp[0] > 0:
        return "frees a stack frame it never made"
    if sp and max(sp) < 0 and not ret and last == "j":
        return "jumps away with its stack frame still in use"
    if early:
        return f"starts by reading {', '.join(REG_NAMES[r] for r in sorted(early))}, set by other code"
    if touched - saved:
        return f"uses {', '.join(REG_NAMES[r] for r in sorted(touched - saved))} without saving them"
    # a compare branch overwritten by a binary patch: `li rX, K; nop; nop`, then rX is written again before any
    # read (none of the 3244 matched functions has it; func_0021E330 has six)
    for i in range(len(ins) - 3):
        x = ins[i]
        if not (x.getOpcodeName() == "addiu" and x.rs.value == 0 and words[i + 1][1] == 0 == words[i + 2][1]
                and words[i + 3][1] != 0 and not (i and ins[i - 1].hasDelaySlot())):
            continue
        reg = x.rt.value
        for y in ins[i + 3:i + 15]:
            if y.hasDelaySlot() or any(r() and getattr(y, f).value == reg
                                       for r, f in ((y.readsRs, "rs"), (y.readsRt, "rt"), (y.readsRd, "rd"))):
                break
            if any(m() and getattr(y, f).value == reg for m, f in ((y.modifiesRt, "rt"), (y.modifiesRd, "rd"))):
                return "a compare branch was patched out (a dead constant, then nop, nop)"
    return None


def patch_pieces(p: Project) -> dict[str, str]:
    """Functions no C compiles to by itself, with why: code patched into the game
    after it was built (it borrows another function's registers or stack frame),
    and the functions that jump into or out of such code."""
    if p.root in _PIECES:
        return _PIECES[p.root]
    cat = p.category()
    funcs: dict[str, list[tuple[int, int]]] = {}
    for path in sorted(p.root.glob("asm/**/*matchings/**/*.s")):
        if is_module_file(p, path):  # code modules: their own address space (tools/modpiles.py tags their pieces)
            continue
        try:
            text = path.read_text()
        except FileNotFoundError:  # an accept moved it to matchings/ meanwhile; seen there next time
            continue
        words = [(int(m.group(1), 16), int.from_bytes(bytes.fromhex(m.group(2)), "little"))
                 for m in ASM_WORD_RE.finditer(text.split("endlabel")[0])]
        if words:
            funcs.setdefault(path.stem, words)
    # asm segments (asm/<chunk>.s) hold several functions each: read every glabel ... endlabel section
    for path in sorted(p.root.glob("asm/*.s")):
        try:
            text = path.read_text()
        except FileNotFoundError:
            continue
        for sec in re.finditer(r"^glabel (\w+)\n(.*?)^endlabel \1\b", text, re.S | re.M):
            words = [(int(m.group(1), 16), int.from_bytes(bytes.fromhex(m.group(2)), "little"))
                     for m in ASM_WORD_RE.finditer(sec.group(2))]
            if words:
                funcs.setdefault(sec.group(1), words)
    why = {f: r for f, w in funcs.items() if (r := piece_reason(w, cat))}
    # dk.json "patch_pieces" {name: why}: patch-area code none of these rules sees (a lone nop, blanked words)
    for f, r in p.cfg.get("patch_pieces", {}).items():
        if f in funcs:
            why.setdefault(f, r)
    spans = sorted((w[0][0], w[-1][0] + 4, f) for f, w in funcs.items())
    starts = [s[0] for s in spans]
    # .text blobs splat could not disassemble (asm/data/blob_F.s, `nonmatching F, SIZE`) are patch code too
    blobs = []
    for path in sorted(p.root.glob("asm/data/blob_*.s")):
        m = re.search(r"nonmatching (\w+), 0x([0-9A-Fa-f]+)", path.read_text())
        if m:
            start = int(m.group(1).rsplit("_", 1)[-1], 16)
            blobs.append((start, start + int(m.group(2), 16), m.group(1)))
    # Compiled code only ever jumps to a function's start: a `j` into a blob or into the middle of another
    # function marks both sides (func_002514F0 -> blob func_00172510; func_0027F700 -> func_001AAAF0's middle)
    for f, words in funcs.items():
        for vram, word in words:
            x = rabbitizer.Instruction(word, vram, cat)
            if x.getOpcodeName() != "j":
                continue
            dest = x.getInstrIndexAsVram()
            blob = next((b[2] for b in blobs if b[0] <= dest < b[1]), None)
            if blob:
                why.setdefault(f, f"jumps into the .text blob {blob}")
                continue
            i = bisect.bisect_right(starts, dest) - 1
            if i >= 0 and spans[i][0] < dest < spans[i][1] and spans[i][2] != f:
                why.setdefault(f, f"jumps into the middle of {spans[i][2]}")
                why.setdefault(spans[i][2], f"{f} jumps into its middle")
    pieces = set(why)
    called = {rabbitizer.Instruction(word, vram, cat).getInstrIndexAsVram()
              for words in funcs.values() for vram, word in words
              if rabbitizer.Instruction(word, vram, cat).getOpcodeName() == "jal"}
    returns = {f for f, words in funcs.items() for _, word in words if word == 0x03E00008}  # jr $ra
    for f, words in funcs.items():
        for vram, word in words:
            x = rabbitizer.Instruction(word, vram, cat)
            if x.getOpcodeName() != "j":
                continue
            dest = x.getInstrIndexAsVram()
            i = bisect.bisect_right(starts, dest) - 1
            if i < 0 or not spans[i][0] <= dest < spans[i][1] or spans[i][2] == f:
                continue
            other = spans[i][2]
            if other in pieces:
                why.setdefault(f, f"jumps into patch code ({other})")
            if f in pieces and dest != spans[i][0]:
                why.setdefault(other, f"patch code ({f}) jumps into its middle")
            elif f in pieces and dest not in called and other not in returns:
                # patch code returning into the original body: splat split a "function" off at the re-entry point
                # (func_00175E60 -> func_00239E4C, the rest of func_00237730; a tail call to a real function
                # such as func_001893A8 -> func_0018A2B8 lands on code that returns by itself)
                why.setdefault(other, f"patch code ({f}) jumps back into it (nothing calls it, it never returns)")
    _PIECES[p.root] = why
    return why


def git(p: Project, *args, check=True):
    return run(["git", "-c", "user.name=kira-502", "-c", "user.email=kira-502@users.noreply.github.com",
                *args], cwd=p.root, check=check)


# ---------------------------------------------------------------- object files

def elf_function(path: Path, name: str):
    """(words, {insn index: (reloc type, symbol)}) for one function in a
    MIPS ELF32 object, or None when the object has no such function."""
    d = path.read_bytes()
    shoff = struct.unpack_from("<I", d, 0x20)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    secs = [struct.unpack_from("<10I", d, shoff + i * shentsize) for i in range(shnum)]

    def cstr(off):
        return d[off:d.index(b"\0", off)].decode()

    sec_name = lambda i: cstr(secs[shstrndx][4] + secs[i][0])  # noqa: E731
    symtab = next(s for s in secs if s[1] == 2)
    strtab = secs[symtab[6]]
    syms = [struct.unpack_from("<IIIBBH", d, symtab[4] + i * 16) for i in range(symtab[5] // 16)]

    def sym_name(s):
        if s[3] & 0xF == 3:  # STT_SECTION
            return f"<{sec_name(s[5])}>"
        return cstr(strtab[4] + s[0])

    hit = next((s for s in syms if s[5] and s[5] < shnum and sym_name(s) == name), None)
    if hit is None:
        return None
    shndx, value, size = hit[5], hit[1], hit[2]
    if not size:  # fall back to the next function symbol or the section end
        later = [s[1] for s in syms if s[5] == shndx and s[3] & 0xF == 2 and s[1] > value]
        size = (min(later) if later else secs[shndx][5]) - value
    sec = secs[shndx]
    code = d[sec[4] + value:sec[4] + value + size]
    words = list(struct.unpack_from(f"<{len(code) // 4}I", code))
    relocs = {}
    for s in secs:
        if s[1] == 9 and s[7] == shndx:  # SHT_REL for this section
            for j in range(s[5] // 8):
                r_off, r_info = struct.unpack_from("<II", d, s[4] + 8 * j)
                if value <= r_off < value + size:
                    relocs[(r_off - value) // 4] = (r_info & 0xFF, sym_name(syms[r_info >> 8]))
    while words and words[-1] == 0 and (len(words) - 1) not in relocs and len(words) > 2 \
            and words[-2] == 0:  # trailing alignment padding
        words.pop()
    return words, relocs


REL_KIND = {4: "26", 5: "hi", 6: "lo", 7: "gp_rel"}
# A code module's function by its link-time name, <module>_<VRAM> (the module's linker script
# defines one per function start): splat names it func_<VRAM>_<module>.
MOD_ALIAS_RE = re.compile(r"([a-z]\d{3})_([0-9A-F]{8})")


def render(words, relocs, vram, cat, alias=None):
    """Rows of (match key, text). `alias` maps a linker name to the func_ name of its
    address, so a call (or address) by either name is the same."""
    alias = alias or {}

    def canon(sym):
        m = MOD_ALIAS_RE.fullmatch(sym)
        return f"func_{m.group(2)}_{m.group(1)}" if m else alias.get(sym, sym)

    rows = []
    for i, w in enumerate(words):
        ins = rabbitizer.Instruction(w, vram + 4 * i, category=cat)
        text = re.sub(r"\s+", " ", ins.disassemble())
        if ins.isBranch() or (ins.isJump() and not ins.isJumpWithAddress() and not ins.isJrRa()
                              and "$" not in text):
            target = (ins.getBranchVramGeneric() - vram) // 4
            text = re.sub(r"\. \+ 4 \+ \(.*\)$", f"@{target}", text)
        r = relocs.get(i)
        if r is None:
            rows.append(((w, None), text))
            continue
        kind, sym = r
        if kind == 4:
            rows.append(((w & 0xFC000000, canon(sym)), f"{ins.getOpcodeName()} {sym}"))
        else:
            imms = list(re.finditer(r"-?0x[0-9A-Fa-f]+|-?\b\d+\b(?=\()", text))
            if imms:
                m = imms[-1]
                text = text[:m.start()] + f"%{REL_KIND.get(kind, kind)}({sym})" + text[m.end():]
            rows.append(((w & 0xFFFF0000, MOD_ALIAS_RE.fullmatch(sym) and canon(sym) or sym), text))
    return rows


def same(a, b) -> bool:
    if a == b:
        return True
    (wa, sa), (wb, sb) = a, b
    return wa == wb and sa is not None and sb is not None and (sa.startswith("<") or sb.startswith("<"))


def compare(target, cand, vram, cat, alias=None):
    t, c = render(*target, vram, cat, alias), render(*cand, vram, cat, alias)
    sm = difflib.SequenceMatcher(a=[k for k, _ in t], b=[k for k, _ in c], autojunk=False)
    matched, soft, lines = 0, False, []
    for op, a0, a1, b0, b1 in sm.get_opcodes():
        if op == "equal":
            matched += a1 - a0
            continue
        for k in range(max(a1 - a0, b1 - b0)):
            ta = t[a0 + k] if a0 + k < a1 else None
            cb = c[b0 + k] if b0 + k < b1 else None
            if ta and cb and same(ta[0], cb[0]):
                matched += 1
                soft = True
                continue
            idx = f"{a0 + k:4d}" if ta else "   +"
            lines.append(f"{idx}  {(ta[1] if ta else ''):38.38s} | {cb[1] if cb else '(missing)'}")
    return matched, len(t), len(c), soft, lines


# ---------------------------------------------------------------- commands

JTBL_RE = re.compile(r"^dlabel (jtbl_\w+)\n(.*?)^enddlabel \1", re.M | re.S)


def switch_sizes(p: Project) -> dict[str, tuple[int, int]]:
    """Functions whose switch cases splat cut off as separate "functions"
    (a case that ends in jr $ra looks like a function end). Returns
    {name: (start, true size)} for symbol_addrs."""
    funcs = {}
    for f in (p.root / "asm").glob("**/nonmatchings/**/*.s"):
        text = f.read_text()
        m = INSN_RE.search(text)
        if m:
            funcs[f.stem] = (int(m.group(0).split()[2], 16), text)
    starts = sorted(s for s, _ in funcs.values())
    fixes = {}
    for name, (start, text) in funcs.items():
        targets = [int(h, 16) for jm in JTBL_RE.finditer(text)
                   for h in re.findall(r"\.word (?:\.L|func_)([0-9A-F]{8})\b", jm.group(2))]
        if not targets:
            continue
        j = k = bisect.bisect_right(starts, start)
        while k < len(starts) and starts[k] <= max(targets):
            k += 1
        if k > j and k < len(starts):
            fixes[name] = (start, starts[k] - start)
    return fixes


def write_sizes(p: Project, fixes: dict[str, tuple[int, int]]):
    path = p.root / "config/symbol_addrs.txt"
    lines = [ln for ln in path.read_text().splitlines()
             if ln.split(" ", 1)[0] not in fixes]
    lines += [f"{n} = 0x{s:08X}; // type:func size:0x{z:X}" for n, (s, z) in sorted(fixes.items())]
    path.write_text("\n".join(lines) + "\n")


LABEL_DEF_RE = re.compile(r"^\s*(?:jlabel\s+)?\.?L([0-9A-F]{8}):?[ \t]*$", re.M)


def merge_sizes(p: Project) -> dict[str, tuple[int, int]]:
    """Functions that branch into the middle of a neighbour are one function
    that splat cut in two. Returns {first piece: (start, joined size)}."""
    funcs = []
    owner = {}
    for f in (p.root / "asm").glob("**/nonmatchings/**/*.s"):
        text = f.read_text()
        m = INSN_RE.search(text)
        if not m:
            continue
        funcs.append((int(m.group(0).split()[2], 16), f.stem, text))
        for lab in LABEL_DEF_RE.findall(text):
            owner[lab] = f.stem
    funcs.sort()
    pos = {name: i for i, (_, name, _) in enumerate(funcs)}
    reach = list(range(len(funcs)))  # furthest function index each one must absorb
    for i, (_, name, text) in enumerate(funcs):
        for lab in set(re.findall(r"(?<![\w.])\.?L([0-9A-F]{8})\b", text)):
            j = pos.get(owner.get(lab, name), i)
            a, b = min(i, j), max(i, j)
            reach[a] = max(reach[a], b)
    fixes, i = {}, 0
    while i < len(funcs):
        end = reach[i]
        k = i
        while k <= end:  # a joined piece can reach further still
            end = max(end, reach[k])
            k += 1
        if end > i and end + 1 < len(funcs):
            fixes[funcs[i][1]] = (funcs[i][0], funcs[end + 1][0] - funcs[i][0])
        i = end + 1
    return fixes


def make_chunks(p: Project, per_file: int = 50, big: int = 1500):
    """Split the code into C files of about per_file functions each, so builds
    run in parallel and an accept rebuilds one small file. Data that splat
    found inside the code stays raw bytes (textbin). Functions over `big`
    instructions stay plain asm files: Metrowerks takes minutes on mwccgap's
    placeholder for them. Make one a C file when it's time to decompile it."""
    units = []
    for f in (p.root / "asm").glob("**/nonmatchings/**/*.s"):
        text = f.read_text()
        m = re.search(r"/\* [0-9A-F]+ ([0-9A-F]{8})", text)
        if m:
            units.append((int(m.group(1), 16), not re.search(r"^glabel ", text, re.M),
                          len(INSN_RE.findall(text)), f.stem))
    chunks: list[list] = []
    n = 0
    for addr, is_data, size, name in sorted(units):
        if is_data or size > big:
            chunks.append([addr, "textbin" if is_data else "asm", f"{'blob' if is_data else 'big'}_{name}"])
            n = 0
            continue
        if n == 0:
            chunks.append([addr, "c", f"main_{sum(ch[1] == 'c' for ch in chunks):03d}"])
        n = (n + 1) % per_file
    chunks[0][0] = min(chunks[0][0], p.cfg["text_start"])
    p.cfg["chunks"] = chunks


def resplit_fresh(p: Project):
    """Rewrite the splat config and split from scratch, letting splat write a
    new src/main.c. Only for projects with no decompiled C yet."""
    p.save()
    write_splat(p)
    for c_file in (p.root / "src").glob("*.c"):
        c_file.unlink()
    r = p.make("split")
    return p.make("check") if not r.returncode else r


def cmd_new(a):
    disc = Disc(a.disc)
    boot = disc.boot_exe()
    exe_name = boot.split("/")[-1]
    data = disc.read_file(boot)
    img = load_image(data)
    root = Path(a.dir).resolve() if a.dir else GAMES / a.name
    if root.exists() and any(root.iterdir()):
        die(f"{root} already exists")
    shutil.copytree(KIT / "templates/psx", root, dirs_exist_ok=True)
    if img.platform == "ps2":
        shutil.copytree(KIT / "templates/ps2", root, dirs_exist_ok=True)
    (root / "tools/cc.sh").chmod(0o755)
    for sub in ("assets", "config", "src", "work"):
        (root / sub).mkdir(exist_ok=True)
    (root / "assets" / exe_name).write_bytes(data)
    shutil.copy(TC / "src/m2c/m2c_macros.h", root / "include/m2c_macros.h")
    with open(root / "disc_files.txt", "w") as f:
        for e in sorted(disc.walk(), key=lambda e: e.lba):
            f.write(f"{e.lba:8d} {e.size:10d} {'dir ' if e.is_dir else '    '}{e.path}\n")

    text_start, data_start = guess_layout(img)
    gp_uses = count_gp(img, text_start, data_start)
    p = Project(root, {
        "name": a.name, "platform": img.platform, "disc": "your own disc image: its path goes in dk.local.json (not in git)",
        "exe": exe_name, "sha1": hashlib.sha1(data).hexdigest(), "file_size": len(data),
        "offset": img.offset, "vram": img.base, "size": img.size, "bss": img.bss,
        "entry": img.entry, "gp": img.gp, "text_start": text_start, "data_start": data_start,
        "overlays": len(img.overlays), **DEFAULTS, "g": 8 if gp_uses > 200 else 0,
    })
    names: dict[int, str] = {}
    lib_note = "no PS2 library signatures yet; functions keep address names"
    if img.platform == "ps2":
        p.cfg.update(gcc="2.96", cflags="-O2", maspsx="")
    else:
        sdk, names, objs = scan_psyq(img, text_start, data_start)
        p.cfg["psyq"] = sdk
        lib_note = f"PsyQ SDK looks like {sdk[0]}.{sdk[1:]}: {objs} library objects, {len(names)} functions named"
    p.save()
    # the disc image is the user's own: its path stays out of the repository
    (root / "dk.local.json").write_text(json.dumps({"disc": str(Path(a.disc).resolve())}, indent=2) + "\n")
    write_symbols(p, names)
    write_splat(p)

    r = p.make("check")
    for _ in range(5):  # PS2: teach fix_asm.py every instruction GNU as rejects
        if not r.returncode or not p.ps2:
            break
        bad = set()
        for m in re.finditer(r"^(\S+\.s):(\d+): Error:", r.stdout + r.stderr, re.M):
            line = (p.root / m.group(1)).read_text().splitlines()[int(m.group(2)) - 1]
            op = re.search(r"\*/\s+([a-z][\w.]*)", line)
            if op:
                bad.add(op.group(1).split(".")[0])
        if not bad:
            break
        with open(p.root / "config/asm_words.txt", "a") as f:
            f.writelines(f"{b}\n" for b in sorted(bad))
        run(["python3", "tools/fix_asm.py"], cwd=p.root)
        r = p.make("check")
    if r.returncode:
        die(f"first build does not match yet:\n{(r.stdout + r.stderr)[-2500:]}")
    if p.ps2:
        # Cuts show up only once the code sits in separate files, so split,
        # look for functions that jump into a neighbour, rejoin, and repeat.
        joined: dict[str, tuple[int, int]] = {}
        for _ in range(6):
            new = {k: v for k, v in merge_sizes(p).items() if joined.get(k) != v}
            if not new and p.cfg.get("chunks"):
                break
            joined.update(new)
            write_sizes(p, joined)
            p.cfg.pop("chunks", None)
            for step in ("rejoining functions", "splitting into files"):
                if step == "splitting into files":
                    make_chunks(p)
                r = resplit_fresh(p)
                if r.returncode:
                    die(f"build stopped matching after {step}:\n{(r.stdout + r.stderr)[-2500:]}")
        big = [c[2] for c in p.cfg["chunks"] if c[1] == "asm"]
        print(f"rejoined {len(joined)} functions splat had cut apart; {len(big)} giant functions kept as "
              f"plain asm files ({', '.join(b[4:] for b in big)})")
        p.cfg["gcc_ranges"] = gcc_ranges(p)
        for a, b in p.cfg["gcc_ranges"]:
            print(f"GCC-built code 0x{a:08X}-0x{b:08X} (likely Sony SDK libraries) is skipped as library code")
    ro = find_rodata(p) if img.platform == "psx" else None
    rodata_note = "switch tables stay with the data for now"
    if ro:
        p.cfg["rodata"] = list(ro)
        r = resplit_fresh(p)
        if r.returncode:
            del p.cfg["rodata"]
            r = resplit_fresh(p)
            if r.returncode:
                die(f"build stopped matching after the rodata attempt:\n{(r.stdout + r.stderr)[-2500:]}")
            rodata_note = "rodata could not be attached to the code; switch functions stay in asm"
        else:
            rodata_note = f"rodata 0x{ro[0]:08X}-0x{ro[1]:08X} travels with its functions"
    fixes: dict[str, tuple[int, int]] = {}
    for _ in range(3):  # a repaired function can reveal the next one
        new = switch_sizes(p)
        if not new:
            break
        fixes.update(new)
        write_sizes(p, fixes)
        r = resplit_fresh(p)
        if r.returncode:
            die(f"build stopped matching after rejoining switch cases:\n{(r.stdout + r.stderr)[-2500:]}")
    if fixes:
        rodata_note += f"; rejoined split-off switch cases in {len(fixes)} functions"
    funcs = p.remaining()
    p.cfg["functions"] = len(funcs)
    p.cfg["code_bytes"] = sum(4 * asm_info(p.func_asm(f))[0] for f in funcs)
    p.save()
    git(p, "init", "-q", "-b", "main")
    git(p, "add", "-A")
    git(p, "commit", "-qm", f"Split {exe_name}: all functions in assembly, build matches")
    print(f"{a.name}: {exe_name} ({img.platform}), {img.size // 1024} KB of code+data at 0x{img.base:08X}")
    print(f"code 0x{text_start:08X}-0x{data_start:08X}, $gp=0x{img.gp:08X} used {gp_uses} times "
          f"-> -G{p.cfg['g']}")
    if img.overlays:
        print(f"{len(img.overlays)} overlay slots for code loaded later "
              f"({sum(s for _, s in img.overlays) // 1024} KB in total), not split yet")
    print(lib_note)
    print(rodata_note)
    print(f"{p.cfg['functions']} functions to decompile ({p.cfg['code_bytes'] // 1024} KB of code)")
    print(f"build matches the original. Project: {root}")


def cmd_build(a):
    p = Project.find()
    r = p.make("check")
    out = (r.stdout + r.stderr).strip()
    # On success the verdict is make's last stdout line; compiler warnings go to stderr.
    print(out[-2500:] if r.returncode else (r.stdout.strip() or out).splitlines()[-1])
    sys.exit(r.returncode)


def asm_sizes(p: Project, paths: list[Path]) -> int:
    """instructions in these asm files, cached by path and mtime in build/dk_asm_sizes.json (the code modules'
    8,600 files are 200 MB of text; dk progress would read them all on every accept)"""
    cache_path = p.root / "build/dk_asm_sizes.json"
    try:
        cache = json.loads(cache_path.read_text())
    except (FileNotFoundError, ValueError):
        cache = {}
    total, changed = 0, False
    for path in paths:
        key = str(path.relative_to(p.root))
        try:
            mt = path.stat().st_mtime_ns
        except FileNotFoundError:
            continue
        hit = cache.get(key)
        if not hit or hit[0] != mt:
            hit = cache[key] = [mt, len(INSN_RE.findall(path.read_text().split("endlabel")[0]))]
            changed = True
        total += hit[1]
    if changed:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(cache_path, json.dumps(cache))
    return total


def is_module_file(p: Project, path: Path) -> bool:
    """a code module's file (src/mod/*.c, asm/*/mod/...): the overlays tools/modules.py splits beside the exe"""
    return "mod" in path.relative_to(p.root).parts[:3]


def cmd_progress(a):
    p = Project.find()
    allrem = p.remaining()
    # Code modules are counted on a line of their own; the first line stays the executable's.
    rem = {f: c for f, c in allrem.items() if not is_module_file(p, c)}
    mod_rem = [f for f in allrem if f not in rem]
    info = {f: asm_info(p.func_asm(f), p.cfg.get("lib_by_name", True)) for f in rem}
    # Counted from the asm itself, not dk.json's totals from `dk new`: those left out
    # the giant functions kept as plain asm files, and padding is no code to write.
    giants = [asm_info(p.root / "asm" / f"{c[2]}.s")[0] for c in p.cfg.get("chunks", []) if c[1] == "asm"]
    matched = [f for f in p.root.glob("asm/**/matchings/**/*.s")
               if "nonmatchings" not in f.parts and f.stem not in allrem]
    done = [asm_info(f)[0] for f in matched if not is_module_file(p, f)]
    total = sum(done) + sum(n for n, _ in info.values()) + sum(giants)
    pct = 100 * sum(done) / total if total else 0
    print(f"{p.cfg['name']}: {len(done)}/{len(done) + len(rem) + len(giants)} functions in C, "
          f"{4 * sum(done) // 1024}/{4 * total // 1024} KB of code ({pct:.2f}%)")
    mod_done = [f for f in matched if is_module_file(p, f)]
    if mod_rem or mod_done:
        mdone = asm_sizes(p, mod_done)
        mtotal = mdone + asm_sizes(p, [p.func_asm(f) for f in mod_rem])
        print(f"code modules: {len(mod_done)}/{len(mod_done) + len(mod_rem)} functions in C, "
              f"{4 * mdone // 1024}/{4 * mtotal // 1024} KB of code "
              f"({100 * mdone / mtotal if mtotal else 0:.2f}%)")
    vu0 = sum("vu0" in tags for _, tags in info.values())
    patched = sum(f in patch_pieces(p) for f in rem)
    if vu0 or patched:
        print(f"left in asm on purpose: {vu0} vector-unit, {patched} patched in after the build")


def cmd_next(a):
    p = Project.find()
    scores_path = p.root / "work/harvest.json"
    scores = json.loads(scores_path.read_text()) if scores_path.exists() else {}
    rows = []
    for f in p.remaining():
        n, tags = tags_for(p, f)
        if a.near and not 0 < scores.get(f, 0) < 100:
            continue
        if a.all or not skip_tags(p) & set(tags):
            rows.append((-scores.get(f, 0) if a.near else n, n, f, tags))
    rows.sort()
    for _, n, f, tags in rows[:a.n]:
        s = f"{scores[f]:3d}%" if f in scores else "    "
        print(f"{n:5d}  {s}  {f:34s} {' '.join(tags)}")


def make_ctx(p: Project) -> Path:
    # Per-process scratch names: several agents may draft at once.
    src = p.root / f"build/ctx_in.{os.getpid()}.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text('#include "common.h"\n#include "game.h"\n')
    out = p.root / "build/ctx.c"
    fresh = p.root / f"build/ctx.{os.getpid()}.c"
    run([*p.cpp(), "-DM2CTX", "-I", p.root / "include", src, "-o", fresh])
    src.unlink()
    if out.exists() and out.read_bytes() == fresh.read_bytes():
        fresh.unlink()  # unchanged: keep the old file so m2c's parse cache stays valid
    else:
        fresh.replace(out)
    return out


O0_PRAGMA = "#pragma optimization_level 0"
O0_RESET = "#pragma optimization_level reset"


def looks_unoptimised(p: Project, func: str) -> bool:
    """True when nearly every branch or jump delay slot is a nop: code the game
    built without optimisation, which matches with O0_PRAGMA around it."""
    path = next(p.root.glob(f"asm/**/{func}.s"), None)
    if path is None or not p.ps2:
        return False
    found = [(int(m.group(1), 16), int.from_bytes(bytes.fromhex(m.group(2)), "little"))
             for m in ASM_WORD_RE.finditer(path.read_text())]
    jumps = nops = 0
    for i, (vram, word) in enumerate(found[:-1]):
        ins = rabbitizer.Instruction(word, vram, p.category())
        if (ins.isBranch() or ins.isJump()) and not ins.isBranchLikely():
            jumps += 1
            nops += found[i + 1][1] == 0
    return jumps >= 3 and nops >= 0.9 * jumps


def jump_tables(p: Project, func: str, asm: Path) -> tuple[Path, list[Path]]:
    """A PS2 split keeps jump tables in the data file as plain addresses and
    leaves their targets unlabelled; m2c needs both as labels. Writes
    work/<func>.jtbl.s (the tables) and work/<func>.m2c.s (the function with
    labels on the targets) when the function has tables."""
    text = asm.read_text()
    names = list(dict.fromkeys(re.findall(r"%hi\((jtbl_[0-9A-F]{8})\)", text)))
    out, targets = [], set()
    for data in sorted(p.root.glob("asm/data/*.s")) if names else []:
        body = data.read_text()
        for name in names:
            m = re.search(rf"^dlabel {name}\n(.*?)^enddlabel {name}", body, re.M | re.S)
            if m:
                targets |= set(re.findall(r"\.word 0x(00[12][0-9A-F]{5})\b", m.group(1)))
                out.append(f"{name}:\n" + re.sub(r"\.word 0x(00[12][0-9A-F]{5})\b", r".word .L\1", m.group(1)))
    if not out:
        return asm, []
    work = p.root / "work"
    work.mkdir(exist_ok=True)
    tables = work / f"{func}.jtbl.s"
    tables.write_text(".section .rodata\n" + "".join(out))
    labelled = work / f"{func}.m2c.s"
    labelled.write_text(re.sub(r"^(\s*/\* [0-9A-F]+ ([0-9A-F]{8}) [0-9A-F]{8} \*/)",
                               lambda m: (f".L{m.group(2)}:\n" if m.group(2) in targets
                                          and f".L{m.group(2)}:" not in text else "") + m.group(1),
                               text, flags=re.M))
    return labelled, [tables]


def m2c(p: Project, func: str, strict: bool = True) -> str | None:
    asm = p.func_asm(func)
    rodata = sorted(p.root.glob("asm/data/*.rodata.s"))
    if not rodata:
        asm, rodata = jump_tables(p, func, Path(asm))
    target = "mipsee-gcc-c" if p.ps2 else "mipsel-gcc-c"
    if p.ps2:
        # The EE passes arguments 5-8 in $t0-$t3, which m2c's mipsee target calls $a4-$a7;
        # under the splat names it read them as unset registers and dropped the arguments.
        ee = p.root / "work" / f"{func}.ee.s"
        text = re.sub(r"\$t([0-3])\b", lambda m: f"$a{int(m.group(1)) + 4}", Path(asm).read_text())
        # m2c reads a tail call `j g` before its delay slot, so an argument set there
        # (`j g; lw $a1, 0($v1)`) was lost; move the slot's instruction ahead of the j.
        text = re.sub(r"^(\s*/\* [0-9A-F ]+ \*/\s+)(j\s+func_\w+)\n(\s*/\* [0-9A-F ]+ \*/\s+)(?!nop\b)(\S.*)$",
                      lambda m: f"{m.group(1)}{m.group(4)}\n{m.group(3)}{m.group(2)}\n{m.group(3)}nop",
                      text, flags=re.M)
        ee.write_text(text)
        asm = ee
    r = run([sys.executable, TC / "src/m2c/m2c.py", "-t", target, "--valid-syntax",
             "--context", make_ctx(p), asm, *rodata], cwd=p.root, check=False)
    if r.returncode:
        if not strict:
            return None
        die(f"m2c failed on {func}:\n{(r.stdout + r.stderr)[-1500:]}")
    head = '#include "common.h"\n#include "game.h"\n#include "m2c_macros.h"\n\n'
    if looks_unoptimised(p, func):
        return f"{head}{O0_PRAGMA}\n\n{r.stdout}\n{O0_RESET}\n"
    return head + r.stdout


def cmd_draft(a):
    p = Project.find()
    out = p.root / "work" / f"{a.func}.c"
    out.parent.mkdir(exist_ok=True)
    out.write_text(m2c(p, a.func))
    print(out.read_text())


def compiles_warm(p: Project, func: str) -> bool:
    """True when tools/cc.sh compiles func's file warm: listed in config/warm_files.txt
    (paths from the project root), it compiles in one mwccps2 run right after a warm-up
    file, as the original's many-files-per-run build left the compiler."""
    home = p.remaining().get(func)
    path = p.root / "config/warm_files.txt"
    if home is not None and is_module_file(p, home):
        return True  # the game's Makefile compiles every code module warm
    if home is None or not path.exists():
        return False
    listed = {ln.split("#", 1)[0].strip() for ln in path.read_text().splitlines()}
    return home.relative_to(p.root).as_posix() in listed


def gcc_files(p: Project) -> dict[str, tuple[str, int, str]]:
    """config/gcc_files.txt: C files tools/cc.sh compiles with an EE GCC instead of the
    project's compiler (a PS2 game's Sony libraries). Path from the project root ->
    (ee-gcc version, -G value, flags), from lines like `src/main_022.c 2.96 0 -O2`."""
    if not hasattr(p, "_gcc_files"):
        path = p.root / "config/gcc_files.txt"
        rows = [ln.split("#", 1)[0].split(None, 3) for ln in
                (path.read_text().splitlines() if path.exists() else [])]
        p._gcc_files = {r[0]: (r[1], int(r[2]), r[3] if len(r) > 3 else "") for r in rows if len(r) >= 3}
    return p._gcc_files


def func_compiler(p: Project, func: str) -> tuple[str, int, str] | None:
    """The EE GCC settings of func's file when config/gcc_files.txt lists it."""
    home = p.remaining().get(func)
    return gcc_files(p).get(home.relative_to(p.root).as_posix()) if home else None


def link_aliases(p: Project) -> dict[str, str]:
    """Names config/linker_syms.txt gives game addresses (fptosi = 0x001A22C0, the
    compiler's runtime helpers), each mapped to the name the original's asm uses:
    its config/symbol_addrs.txt name, else func_<address>. A renamed function's old func_ name
    (config/old_names.txt) maps to its real name too."""
    out = {old: new for new, old in old_names(p).items() if not new.startswith("0x")}
    path = p.root / "config/linker_syms.txt"
    if not path.exists():
        return out
    sym_re = r"^\s*(\w+)\s*=\s*0x([0-9A-Fa-f]+)\s*;"
    sa = p.root / "config/symbol_addrs.txt"
    named = {int(m.group(2), 16): m.group(1) for m in re.finditer(sym_re, sa.read_text(), re.M)} if sa.exists() else {}
    out.update({m.group(1): named.get(int(m.group(2), 16), f"func_{int(m.group(2), 16):08X}") for m in
                re.finditer(sym_re, path.read_text(), re.M)})
    return out


def try_func(p: Project, func: str, src: Path, **over):
    tdir = p.root / "build/try" / func  # one folder per function, so agents can run side by side
    tdir.mkdir(parents=True, exist_ok=True)
    asm = p.func_asm(func)
    wrap = tdir / f"{func}.target.s"
    wrap.write_text(f'.include "include/macro.inc"\n.set noat\n.set noreorder\n.section .text\n'
                    f'.include "{asm.relative_to(p.root)}"\n')
    tgt = tdir / f"{func}.target.o"
    run(["mipsel-none-elf-as", *p.as_flags(0), "-I", p.root, "-I", p.root / "include", "-o", tgt, wrap],
        cwd=p.root)
    cand = tdir / f"{func}.o"
    cand.unlink(missing_ok=True)
    # A prototype other drafts guessed for this function must not fight its definition.
    shadow = tdir / "inc"
    shadow.mkdir(exist_ok=True)
    game_h = (p.root / "include/game.h").read_text().splitlines()
    (shadow / "game.h").write_text("\n".join(ln for ln in game_h if decl_name(ln) != func) + "\n")
    shutil.copy(p.root / "include/common.h", shadow / "common.h")  # quoted includes look beside it first
    lib = func_compiler(p, func)  # a file of Sony library code compiles with its own GCC
    if lib and over.get("gcc") is None:
        over = {**over, "gcc": lib[0], "g": lib[1] if over.get("g") is None else over["g"],
                "cflags": lib[2] if over.get("cflags") is None else over["cflags"]}
    env = p.env(**over)
    env["DK_EXTRA_INCLUDE"] = str(shadow)
    # The copy compiles warm when the function's real file does (an exported DK_WARM wins).
    env.setdefault("DK_WARM", "1" if compiles_warm(p, func) else "0")
    # The 32-bit preprocessor can't stat files on /mnt/c (inode numbers too big),
    # so it always compiles a copy that lives in the project.
    local = tdir / f"{func}.c"
    if src.resolve() != local.resolve():
        shutil.copy(src, local)
    r = run([p.root / "tools/cc.sh", local, cand], cwd=p.root, env=env, check=False)
    if r.returncode:
        return None, (r.stdout + r.stderr).strip()
    target, mine = elf_function(tgt, func), elf_function(cand, func)
    if mine is None:
        return None, f"{func} is not defined in {src}"
    first = INSN_RE.search(asm.read_text())
    vram = int(first.group(0).split()[2], 16) if first else 0
    return compare(target, mine, vram, p.category(), link_aliases(p)), ""


MW_FILE_RE = re.compile(r"^#\s+File:\s+(\S+)")
MW_LINE_RE = re.compile(r"^#\s+(\d+):\s?(.*)$")


def mw_errors(output: str, root: Path | None = None) -> list[tuple[str, int, str, str]]:
    """(file, line, source line, message) for each Metrowerks error (not warning)
    in its output. mwccgap compiles a temporary copy of the file; with `root`
    given, the copy's name is traced back to the real file in src/."""
    out = []
    file, num, srcline, msg, error = "", 0, "", [], False

    def flush():
        if msg and error:
            real = file
            if root is not None and file.startswith("tmp"):
                real = next((f.name for f in sorted((root / "src").glob("*.c"))
                             if not f.name.startswith("tmp") and srcline in f.read_text()), file)
            out.append((real, num, srcline, " ".join(msg)))

    for ln in output.splitlines():
        if not ln.startswith("#"):
            continue
        m = MW_FILE_RE.match(ln)
        if m:
            file = m.group(1).replace("\\", "/").split("/")[-1]
            continue
        m = MW_LINE_RE.match(ln)
        if m:
            flush()
            num, srcline, msg, error = int(m.group(1)), m.group(2).strip(), [], False
            continue
        body = ln.strip("# ")
        if body.startswith("Error:"):
            error = True
        elif body.startswith("Warning:"):
            error = False
        elif body and not body.startswith(("-", "mwccps2", "In:", "From:")) and "^" not in body:
            msg.append(body)
    flush()
    return out


def context_check(p: Project, func: str, text: str) -> tuple[list[str], list[str], int]:
    """Place the work file the way dk accept will, in a scratch copy of src/ and
    include/ (headers synced, stale prototypes dropped), and compile every C file
    the change touches or that mentions the function. Catches the clashes that
    otherwise only the full build finds. Returns (complaints about lines from the
    work file, complaints about other code, files compiled)."""
    shadow = p.root / "build/try" / func / "proj"
    shutil.rmtree(shadow, ignore_errors=True)
    shadow.mkdir(parents=True)
    for name in ("src", "include"):
        shutil.copytree(p.root / name, shadow / name, ignore=shutil.ignore_patterns("tmp*.c"))
    for name in ("asm", "assets", "tools", "config", "dk.json", "config.mk", "Makefile"):
        if (p.root / name).exists():
            (shadow / name).symlink_to(p.root / name)
    sp = Project(shadow)
    before = {f: f.read_text() for f in sp.c_files()}
    try:
        apply_funcs(sp, {func: text})
    except SystemExit:
        return ["the work file has no definition of the function"], [], 0
    call_re = re.compile(rf"\b{re.escape(func)}\s*\(")
    targets = [f for f in sp.c_files() if f.read_text() != before.get(f) or call_re.search(f.read_text())]
    own_lines = {ln.strip() for ln in text.splitlines() if ln.strip()}
    own, other = [], []
    for cfile in targets:
        r = run([shadow / "tools/cc.sh", cfile, shadow / "build/ctx" / f"{cfile.name}.o"],
                cwd=shadow, env=p.env(), check=False)
        if r.returncode:
            errs = mw_errors(r.stdout + r.stderr, shadow)
            if not errs:
                own.append(f"{cfile.name}: " + (r.stdout + r.stderr).strip().splitlines()[-1][:200])
            for file, num, srcline, msg in errs:
                (own if srcline in own_lines else other).append(f"{file}:{num}: {srcline}  -> {msg}")
    return own, other, len(targets)


def cmd_try(a):
    p = Project.find()
    src = Path(a.file).resolve() if a.file else p.root / "work" / f"{a.func}.c"
    res, err = try_func(p, a.func, src, gcc=a.gcc, g=a.g, cflags=a.cflags)
    if res is None:
        print("COMPILE ERROR\n" + "\n".join(err.splitlines()[-25:]))
        sys.exit(2)
    matched, nt, nc, soft, lines = res
    if matched == nt == nc:
        note = " (data references get confirmed by the full build)" if soft else ""
        if not a.no_context and a.func in p.remaining():
            own, other, n = context_check(p, a.func, src.read_text())
            if own:
                print(f"CLASH {a.func}: the code matches on its own, but lines from your file do not fit "
                      f"the game. Placed in its file, the compiler says:")
                for c in own[:8]:
                    print("  " + c)
                print("Change your file to fit the existing declarations (include/functions.h, game.h, "
                      "structs.h), then try again.")
                sys.exit(4)
            if other:
                print(f"BLOCKED BY CALLER {a.func}: your code matches and fits, but other code that is "
                      f"already in the game does not compile with it:")
                for c in other[:8]:
                    print("  " + c)
                decl = re.compile(rf"^\s*(?!return\b)(?:extern\s+)?(?:\w+[\s\*]+)+{re.escape(a.func)}\s*\([^;{{&=]*\)\s*;")
                seen = []
                for name in dict.fromkeys(c.split(":", 1)[0] for c in other):
                    path = p.root / "src" / name
                    for num, ln in enumerate(path.read_text().splitlines() if path.exists() else [], 1):
                        if decl.match(ln) and len(seen) < 6:
                            seen.append(f"  {name}:{num}: {ln.strip()}")
                print("Usually this is only a type. dk accept deletes the callers' own file-level guesses, so every "
                      "caller then sees YOUR prototype: give your function the types the callers already use "
                      "(parameters AND return width: a GCC caller that uses the result as u64 or long needs that "
                      "return type), keeping the body; if a C body can't take the type, an inline-asm body can.")
                if seen:
                    print("The callers declare it as:")
                    print("\n".join(seen))
                print("A caller that passes no arguments needs a block-scope `extern void F();` in that caller "
                      "(a lock-routine fix). Report `blocked by caller: <file:line>` only if no type fits every caller.")
                sys.exit(5)
            note += f"; fits in the game ({n} file{'s' if n != 1 else ''} compiled)"
        print(f"MATCH {a.func}: {nt} instructions{note}. Next: dk accept {a.func}")
        return
    print(f"{a.func}: {matched}/{nt} instructions match ({100 * matched / nt:.0f}%), yours has {nc}")
    if O0_PRAGMA not in src.read_text() and looks_unoptimised(p, a.func):
        print(f"HINT: this function was built without optimisation (almost every delay slot is a nop). "
              f"Put `{O0_PRAGMA}` on a line before it and `{O0_RESET}` after it.")
    print("   #  original                               | yours")
    for line in lines[:a.lines]:
        print(line)
    if len(lines) > a.lines:
        print(f"   ... {len(lines) - a.lines} more")
    sys.exit(3)


def split_work(func: str, text: str) -> tuple[str, list[str], str]:
    """(function definition, one-line declarations above it, local code above it)
    from a work file. Plain declarations go to game.h. A file that also has
    types, helper functions or #defines keeps its whole preamble beside the
    function instead, since its declarations may use those types."""
    m = re.search(rf"^[A-Za-z_][\w \t\*]*?\b{re.escape(func)}\s*\([^;{{]*\)\s*\{{", text, re.M)
    if not m:
        die(f"no definition of {func} in its work file")
    pre = [ln for ln in text[:m.start()].splitlines() if not ln.startswith("#include")]
    code = [ln for ln in pre if ln.strip() and not ln.lstrip().startswith("//")]
    if all(decl_name(ln) for ln in code):
        return text[m.start():].strip(), code, ""
    return text[m.start():].strip(), [], "\n".join(pre).strip()


LOCAL_TYPE_RE = re.compile(r"}\s*(\w+)\s*;|typedef\s+[^;{}]*?\b(\w+)\s*;|\bstruct\s+(\w+)\s*\{")


def local_types(code: str) -> set[str]:
    """Type names that a work file's local code declares (typedefs, struct tags)."""
    return {n for m in LOCAL_TYPE_RE.finditer(code) for n in m.groups() if n}


DEF_RE = re.compile(r"^([A-Za-z_][\w \t\*]*?\b(\w+)\s*\([^;{]*\))\s*\{", re.M)


def decl_name(line: str) -> str | None:
    """Name declared by a one-line extern or prototype."""
    s = re.sub(r"/\*.*?\*/|//.*$", "", line).strip()
    if not s.endswith(";"):
        return None
    m = re.search(r"\(\s*\*\s*(\w+)\s*\)", s) or re.search(r"(\w+)\s*\(", s) \
        or re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*(?:=.*)?;$", s)
    return m.group(1) if m else None


def defined_functions(p: Project) -> dict[str, str]:
    out = {}
    for f in p.c_files():
        for m in DEF_RE.finditer(f.read_text()):
            # a Metrowerks `asm int f(...) {` function: the prototype is plain C for the GCC files too
            out[m.group(2)] = re.sub(r"^asm\s+", "", " ".join(m.group(1).split()))
    return out


def stale_decl(line: str, defs: dict[str, str]) -> bool:
    """A top-level one-line prototype of a function that functions.h now
    declares exactly (a guess that a work file's preamble left in src/)."""
    if not line or line[0].isspace() or line.startswith(("#", "INCLUDE_ASM", "static", "return", "typedef")):
        return False
    return "(" in line and line.rstrip().endswith(";") and decl_name(line) in defs


# C library names the compilers treat as built-ins: a call by such a name may be inlined (EE GCC: memcpy,
# memset, memcmp with a constant size, strlen of a literal; Metrowerks: abs), so code keeps calling a function
# given one of these names by its old name.
C_BUILTINS = frozenset("""memchr abs labs fabs fabsf ffs memcpy memcmp memset memmove strcmp strcpy strlen strncpy
strncmp strcat strncat strchr strrchr strstr strpbrk strspn strcspn sqrt sqrtf sin sinf cos cosf alloca bzero bcmp
bcopy index rindex printf fprintf sprintf puts fputs fputc putchar exit abort _exit floor ceil exp log pow atan
atan2 tan bsearch qsort malloc free calloc realloc fwrite""".split())


def old_names(p: Project) -> dict[str, str]:
    """Real name -> the old func_<address> name it replaced (config/old_names.txt, `func_X = Name;`, which the
    main link uses as aliases). Empty for a project whose functions keep their func_ names."""
    path = p.root / "config/old_names.txt"
    if not path.exists():
        return {}
    return {new: old for old, new in re.findall(r"^(func_[0-9A-F]{8}) = (\w+);", path.read_text(), re.M)}


def old_name_protos(p: Project, defs: dict[str, str], game_lines: list[str]) -> str:
    """functions.h's block of old names: every renamed function's prototype (its definition's, else its game.h
    guess) under its old func_ name, for the code that still calls it so (code modules, built-in names). The EE
    GCC files see only the built-in ones: their code changes with the set of names declared."""
    old = old_names(p)
    if not old:
        return ""
    protos = {n: re.sub(rf"\b{n}\b", old[n], sig, count=1) + ";" for n, sig in defs.items() if n in old}
    for ln in game_lines:
        n = decl_name(ln) if "(" in ln and not ln[:1].isspace() else None
        if n in old and n not in protos:
            protos[n] = re.sub(rf"\b{n}\b", old[n], re.sub(r"/\*.*?\*/|//.*$", "", ln).strip(), count=1)
    rows = sorted((old[n], n, s) for n, s in protos.items())
    return ("\n/* Old names of renamed functions (config/old_names.txt): code modules and calls of C library\n"
            "   built-in names use them. dk writes this block too. */\n"
            + "".join(f"{s}\n" for _, n, s in rows if n in C_BUILTINS)
            + "#ifndef __GNUC_MINOR__ /* not EE GCC */\n"
            + "".join(f"{s}\n" for _, n, s in rows if n not in C_BUILTINS) + "#endif\n")


def sync_headers(p: Project) -> dict[Path, str]:
    """functions.h gets the exact prototype of every decompiled function; game.h
    and the C files lose any guessed prototype for those names. Returns the old
    text of the C files it changed, so a failed accept can put them back."""
    # A static helper belongs to its own file; in the shared header its local types break the others.
    defs = {n: sig for n, sig in defined_functions(p).items() if not sig.startswith("static")}
    game_h = p.root / "include/game.h"
    keep = [ln for ln in game_h.read_text().splitlines()
            if not ("(" in ln and decl_name(ln) in defs)]
    write_atomic(game_h, "\n".join(keep) + "\n")
    # config/jp_names.txt (`func_XXXXXXXX<TAB>name`): the real name goes beside the prototype as a comment.
    names_path = p.root / "config/jp_names.txt"
    names = dict(ln.split("\t", 1) for ln in names_path.read_text().splitlines()
                 if "\t" in ln and not ln.startswith("#")) if names_path.exists() else {}
    write_atomic(p.root / "include/functions.h",
        "#ifndef FUNCTIONS_H\n#define FUNCTIONS_H\n\n"
        "/* Prototypes of every decompiled function. dk rewrites this file. */\n"
        + "".join(f"{sig};" + (f" /* JP: {names[n]} */" if n in names else "") + "\n"
                  for n, sig in sorted(defs.items())) + old_name_protos(p, defs, keep) + "\n#endif\n")
    changed = {}
    for cfile in p.c_files():
        text = cfile.read_text()
        lines = text.split("\n")
        keep = [ln for ln in lines if not stale_decl(ln, defs)]
        if len(keep) != len(lines):
            changed[cfile] = text
            write_atomic(cfile, "\n".join(keep))
    return changed


def apply_funcs(p: Project, items: dict[str, str]) -> dict[Path, str]:
    """Swap each function's INCLUDE_ASM for its C. Returns the files' old
    contents so a failed build can be rolled back."""
    rem = p.remaining()
    game_h, funcs_h = p.root / "include/game.h", p.root / "include/functions.h"
    old = {game_h: game_h.read_text(), funcs_h: funcs_h.read_text() if funcs_h.exists() else ""}
    decls_all: list[str] = []
    for func, text in items.items():
        body, decls, local = split_work(func, text)
        cfile = rem[func]
        if cfile not in old:
            old[cfile] = cfile.read_text()
        code = f"{local}\n\n{body}" if local else body
        line_re = re.compile(rf'^INCLUDE_ASM\("[^"]+",\s*{re.escape(func)}\);[ \t]*$', re.M)
        write_atomic(cfile, line_re.sub(lambda _: code, cfile.read_text(), count=1))
        decls_all += decls
    defined = defined_functions(p)
    known = {decl_name(ln) for ln in old[game_h].splitlines()} - {None}
    new = []
    for d in decls_all:
        n = decl_name(d)
        if n and n not in known and n not in defined:
            known.add(n)
            new.append(d)
    if new:
        head, _, tail = old[game_h].rpartition("#endif")
        write_atomic(game_h, head + "\n".join(new) + "\n\n#endif" + tail)
    for path, text in sync_headers(p).items():
        old.setdefault(path, text)
    return old


def write_atomic(path: Path, text: str):
    """Write through a temporary file and a rename, so an agent compiling at the
    same moment never reads a half-written header."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def restore(old: dict[Path, str]):
    for path, text in old.items():
        write_atomic(path, text)


def clean_check(p: Project):
    """Full build check with every C file recompiled: a header change from one
    accept can break a file that make would otherwise reuse stale. A game with code
    modules (src/mod, tools/modules.py) keeps their objects: they carry no header
    dependencies, the module whose C file an accept changed rebuilds anyway, and all
    762 from scratch cost minutes."""
    src = p.root / "build/src"
    if not (src / "mod").is_dir():
        shutil.rmtree(src, ignore_errors=True)
    else:
        for f in src.iterdir():
            if f.name == "mod":
                continue
            if f.is_dir():
                shutil.rmtree(f, ignore_errors=True)
            else:
                f.unlink(missing_ok=True)
    return p.make("check")


def changed_functions(p: Project, limit: int = 6) -> list[str]:
    """Functions whose bytes differ between the built executable and the original."""
    exe = p.root / "build" / p.cfg["exe"]
    if not exe.exists():
        return []
    a, b = (p.root / "assets" / p.cfg["exe"]).read_bytes(), exe.read_bytes()
    syms = sorted((int(m.group(1), 16), m.group(2)) for m in
                  (re.match(r"\s+0x([0-9a-f]+)\s+(\w+)$", ln) for ln in
                   (p.root / "build/main.map").read_text().splitlines()) if m)
    addrs = [v for v, _ in syms]
    seen: list[str] = []
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            k = bisect.bisect_right(addrs, i - p.cfg["offset"] + p.cfg["vram"]) - 1
            name = syms[k][1] if k >= 0 else "?"
            if name not in seen:
                seen.append(name)
                if len(seen) >= limit:
                    break
    if len(a) != len(b):
        seen.append(f"(size {len(b)} instead of {len(a)})")
    return seen


def build_failure(p: Project, r) -> str:
    """Why a failed full build failed: the first compiler error, else the
    functions whose bytes changed."""
    errs = mw_errors(r.stdout + r.stderr, p.root)
    if errs:
        file, num, srcline, msg = errs[0]
        return f"compile error in {file}:{num}: {srcline} -> {msg}"
    names = changed_functions(p)
    return "bytes differ in " + ", ".join(names) if names else "the full build no longer matches"


def accept_many(p: Project, items: dict[str, str], why: dict[str, str] | None = None) -> list[str]:
    """Accept as many functions as keep the build matching; halves the batch
    whenever the build breaks, so one bad function can't block the rest.
    `why` collects the failure of each function rejected on its own."""
    done: list[str] = []

    def attempt(names: list[str]):
        if not names:
            return
        old = apply_funcs(p, {n: items[n] for n in names})
        r = clean_check(p)
        if r.returncode == 0:
            done.extend(names)
            return
        if len(names) == 1 and why is not None:
            why[names[0]] = build_failure(p, r)
        restore(old)
        if len(names) > 1:
            attempt(names[:len(names) // 2])
            attempt(names[len(names) // 2:])

    attempt(list(items))
    file_as_matched(p, done)
    return done


@contextmanager
def project_lock(p: Project):
    """One accept, revert or harvest at a time per project: each rewrites src/
    and include/, runs a full build and commits. Helpers and runners share it."""
    path = p.root / "work/.accept.lock"
    path.parent.mkdir(exist_ok=True)
    with open(path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def file_as_matched(p: Project, funcs: list[str]):
    """Move accepted functions' asm from nonmatchings/ to matchings/, where a
    re-split would put it, so nonmatchings/ lists only what is still asm
    (coddog reads it to label decompiled look-alikes)."""
    for func in funcs:
        asm = next(p.root.glob(f"asm/**/nonmatchings/**/{func}.s"), None)
        if asm:
            done = Path(str(asm).replace("/nonmatchings/", "/matchings/", 1))
            done.parent.mkdir(parents=True, exist_ok=True)
            asm.replace(done)


def cmd_accept(a):
    p = Project.find()
    work = Path(a.file).resolve() if a.file else p.root / "work" / f"{a.func}.c"
    text = work.read_text()
    body, decls, local = split_work(a.func, text)
    if "M2C_" in body + local or any("M2C_" in d for d in decls):
        die("the draft still has M2C_ placeholders; replace them with real C first")
    sig = body.split("{", 1)[0]
    # a static function stays out of functions.h (sync_headers), so its signature may name its file's types
    clash = [] if sig.lstrip().startswith("static") else \
        sorted(t for t in local_types(local) if re.search(rf"\b{re.escape(t)}\b", sig))
    if clash:
        die(f"{a.func}'s signature uses {', '.join(clash)}, declared only in its own file, so "
            "functions.h can't name it for other files. Use a plain pointer there and cast inside.")
    with project_lock(p):
        if a.func not in p.remaining():
            die(f"{a.func} is not waiting as INCLUDE_ASM in src/ (already accepted?)")
        old = apply_funcs(p, {a.func: text})
        r = clean_check(p)
        if r.returncode:
            restore(old)
            print(f"REJECTED ({build_failure(p, r)}), so nothing was changed.")
            print("\n".join((r.stdout + r.stderr).strip().splitlines()[-15:]))
            sys.exit(1)
        git(p, "add", "src", "include")
        git(p, "commit", "-qm", f"Match {a.func}")
        file_as_matched(p, [a.func])
    print(f"ACCEPTED {a.func}: build still matches the original; committed.")
    cmd_progress(a)


def function_span(text: str, func: str) -> tuple[int, int] | None:
    """Start and end of a function definition in C source."""
    m = re.search(rf"^[A-Za-z_][\w \t\*]*?\b{re.escape(func)}\s*\([^;{{]*\)\s*\{{", text, re.M)
    if not m:
        return None
    depth = 0
    for i in range(m.end() - 1, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return m.start(), i + 1
    return None


def cmd_revert(a):
    """Put a decompiled function back to its original asm (its prototype
    moves to game.h so callers in C still see it)."""
    p = Project.find()
    with project_lock(p):
        revert_func(p, a)


def revert_func(p: Project, a):
    for cfile in p.c_files():
        text = cfile.read_text()
        span = function_span(text, a.func)
        if span:
            break
    else:
        die(f"{a.func} is not defined in src/")
    other = INCLUDE_RE.search(text)
    folder = other.group(1) if other else f"asm/nonmatchings/{cfile.stem}"
    sig = " ".join(text[span[0]:span[1]].split("{", 1)[0].split())
    game_h = p.root / "include/game.h"
    old = {cfile: text, game_h: game_h.read_text(), p.root / "include/functions.h":
           (p.root / "include/functions.h").read_text()}
    cfile.write_text(text[:span[0]] + f'INCLUDE_ASM("{folder}", {a.func});' + text[span[1]:])
    head, _, tail = old[game_h].rpartition("#endif")
    write_atomic(game_h, head + f"{sig};\n\n#endif" + tail)
    sync_headers(p)
    # A split made after the function was decompiled filed its asm under
    # matchings/; splitting again files it with the other asm functions.
    if not (p.root / folder / f"{a.func}.s").exists():
        p.make("split")
    r = clean_check(p)
    if r.returncode:
        restore(old)
        die("the build does not match with this function back in asm either; nothing changed:\n"
            + "\n".join((r.stdout + r.stderr).strip().splitlines()[-10:]))
    git(p, "add", "src", "include")
    git(p, "commit", "-qm", f"Return {a.func} to asm{': ' + a.why if a.why else ''}")
    print(f"{a.func} is asm again; build matches; committed.")


def plain_draft(draft: str) -> str | None:
    """m2c draft with unknown types guessed as s32 (dk try proves or refutes
    the guess), or None when it still needs a human."""
    draft = draft.replace("M2C_UNK", "s32").replace('#include "m2c_macros.h"\n', "")
    if "M2C_" in draft or "Decompilation failure" in draft:
        return None
    return draft


def cmd_harvest(a):
    p = Project.find()
    rows = []
    for f in p.remaining():
        n, tags = tags_for(p, f)
        if n <= a.max and not skip_tags(p) & set(tags):
            rows.append((n, f))
    rows.sort()
    picks = [f for _, f in rows[:a.n]]
    good: dict[str, str] = {}
    scores_path = p.root / "work/harvest.json"
    scores = json.loads(scores_path.read_text()) if scores_path.exists() else {}
    for i, f in enumerate(picks, 1):
        draft = m2c(p, f, strict=False)
        draft = plain_draft(draft) if draft else None
        if draft is None:
            continue
        path = p.root / "work" / f"{f}.c"
        path.parent.mkdir(exist_ok=True)
        path.write_text(draft)
        res, _ = try_func(p, f, path)
        if res:
            scores[f] = round(100 * res[0] / max(res[1], res[2]))
            if res[0] == res[1] == res[2]:
                good[f] = draft
        if i % 100 == 0:
            print(f"  checked {i}/{len(picks)}, {len(good)} match so far", flush=True)
    scores_path.write_text(json.dumps(scores, indent=0))
    print(f"{len(good)}/{len(picks)} functions match straight from the m2c draft")
    near = sum(1 for f, s in scores.items() if 85 <= s < 100 and f not in good)
    print(f"{near} more are within 85-99% (see dk next --near)")
    if a.dry_run or not good:
        return
    with project_lock(p):
        done = accept_many(p, good)
        if done:
            git(p, "add", "src", "include")
            git(p, "commit", "-qm", f"Harvest {len(done)} functions that m2c matched without edits")
    print(f"accepted {len(done)} (build still matches; committed), {len(good) - len(done)} rejected by the full build")
    cmd_progress(a)


def cmd_perm(a):
    p = Project.find()
    src = Path(a.file).resolve() if a.file else p.root / "work" / f"{a.func}.c"
    res, err = try_func(p, a.func, src)
    if res is None:
        die("the C does not compile yet:\n" + "\n".join(err.splitlines()[-15:]))
    if res[0] == res[1] == res[2]:
        print(f"{a.func} already matches; run dk accept {a.func}")
        return
    d = p.root / "nonmatchings" / a.func
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    # try_func's shadow game.h drops the guessed prototype that would fight the definition
    run([*p.cpp(), "-DPERMUTER", "-I", p.root / "build/try" / a.func / "inc", "-I", p.root / "include",
         "-I", p.root / "src", src, "-o", d / "base.c"])
    shutil.copy(p.root / "build/try" / a.func / f"{a.func}.target.o", d / "target.o")
    (d / "compile.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        'INPUT="$(realpath "$1")"\nOUTPUT="$(realpath "$3")"\n'
        f"cd {shlex.quote(str(p.root))}\n"
        f"export DK_TOOLCHAIN={shlex.quote(str(TC))} PATH={shlex.quote(str(TC / 'bin'))}:$PATH\n"
        f"export DK_WARM={'1' if compiles_warm(p, a.func) else '0'}\n"
        'exec tools/cc.sh "$INPUT" "$OUTPUT"\n')
    (d / "compile.sh").chmod(0o755)
    (d / "settings.toml").write_text(
        f'func_name = "{a.func}"\ncompiler_type = "gcc"\n'
        f'objdump_command = "mipsel-none-elf-objdump -drz -m mips:{5900 if p.ps2 else 3000}"\n')
    print(f"{a.func}: {res[0]}/{res[1]} instructions match; permuting for up to {a.minutes} min "
          f"on {a.jobs} threads...", flush=True)
    subprocess.run(["timeout", "--signal=INT", str(a.minutes * 60), sys.executable,
                    TC / "src/decomp-permuter/permuter.py", d, "-j", str(a.jobs),
                    "--stop-on-zero", "--best-only", "--quiet"],
                   cwd=p.root, capture_output=True, text=True)
    outs = sorted(d.glob("output-*"), key=lambda o: int(o.name.split("-")[1]))
    if not outs:
        print("no better version found")
        sys.exit(3)
    best = outs[0]
    score = int(best.name.split("-")[1])
    body, _, _ = split_work(a.func, (best / "source.c").read_text())
    head = src.read_text()[:re.search(rf"^[A-Za-z_][\w \t\*]*?\b{re.escape(a.func)}\s*\(",
                                      src.read_text(), re.M).start()]
    out = p.root / "work" / f"{a.func}.perm.c"
    out.write_text(head + body + "\n")
    print(f"best permuter score {score} (0 = exact); saved {out.relative_to(p.root)}")
    print(f"check it: dk try {a.func} work/{out.name}")


def cmd_ghidra(a):
    """Ghidra's C for functions: a second, readable view next to the m2c draft.
    Ghidra analyses the whole program once (about 2 minutes), so it follows
    calls and data that m2c can't see."""
    p = Project.find()
    if not p.ps2:
        die("dk ghidra handles PS2 games only so far")
    headless = next((TC / "ghidra").glob("ghidra_*/support/analyzeHeadless"), None)
    if headless is None:
        die("Ghidra is not installed; run setup/toolchain.sh")
    proj, exe = p.root / "ghidra", p.cfg["exe"]
    proj.mkdir(exist_ok=True)
    out = proj / f"out.{os.getpid()}.c"
    # One Ghidra run at a time per project: its database takes a lock.
    with open(proj / "dk.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (proj / f"{p.cfg['name']}.gpr").exists():
            mode = ["-process", exe, "-noanalysis"]
        else:
            print("first run: Ghidra is analysing the whole program (about 2 minutes)", file=sys.stderr)
            mode = ["-import", p.root / "assets" / exe, "-processor", "r5900:LE:32:default"]
        # Teach Ghidra what the C knows (types, globals, prototypes, names) whenever that changed.
        from dklib.ghidra_types import write_inputs
        tdir = p.root / "build/ghidra"
        summary, text = write_inputs(p.root, p.cpp(), tdir)
        script = (KIT / "dklib/ghidra/ApplyTypes.java").read_text()
        stamp = hashlib.sha1((text + (tdir / "labels.txt").read_text() + script).encode()).hexdigest()
        stamp_file = proj / "types.stamp"
        teach = []
        if a.refresh or not stamp_file.exists() or stamp_file.read_text().strip() != stamp:
            bss = p.cfg["vram"] + p.cfg["size"]
            teach = ["-postScript", "ApplyTypes.java", tdir / "types.h", tdir / "labels.txt",
                     f"{bss:X}", f"{p.cfg.get('bss', 0):X}"]
            print(f"teaching Ghidra the C: {summary}", file=sys.stderr)
        r = run([headless, proj, p.cfg["name"], *mode, "-scriptPath", KIT / "dklib/ghidra", *teach,
                 "-postScript", "DecompileFunctions.java", out, *a.funcs], check=False)
        if teach and "dk-types:" in r.stdout + r.stderr and out.exists():
            stamp_file.write_text(stamp + "\n")
    if not out.exists():
        die("Ghidra failed:\n" + (r.stdout + r.stderr)[-3000:])
    text = out.read_text().strip()
    out.unlink()  # before printing: a reader that hangs up early must not leave it behind
    print(text)


GRIND_PROMPT = (
    "You are one worker in a matching-decompilation run. First read work/gpt/PLAYBOOK.md and "
    "follow it exactly. It has the commands, the rules, the compiler facts and the report format.\n\n"
    "Then work this one function: {func} ({insns} instructions). Start from a fresh draft as the "
    "playbook says.{hints}\n\nDon't read other files or docs beyond what the playbook's commands show you. "
    "Your final message must be only the report line the playbook describes.\n")
RETRY_PROMPT = (
    "You are one worker in a matching-decompilation run. First read work/gpt/PLAYBOOK.md and "
    "follow it exactly. It has the commands, the rules, the compiler facts and the report format.\n\n"
    "Then work this one function: {func} ({insns} instructions). Your earlier file work/gpt/{func}.c "
    "matched when it was tested alone, but the full game build rejected it, because it clashes with "
    "declarations that other functions brought in since. The build said:\n{errors}\n\n"
    "Do NOT start from a fresh draft: start from work/gpt/{func}.c. Run dk try on it to see the clash "
    "now, change your file to fit the existing declarations (copy prototypes from include/functions.h, "
    "use the global's type from include/game.h or include/structs.h and cast where you need fields), "
    "and keep it matching. Report MATCH only when dk try prints MATCH.{hints}\n\n"
    "Don't read other files or docs beyond what the playbook's commands show you. "
    "Your final message must be only the report line the playbook describes.\n")
NEAR_PROMPT = (
    "You are one worker in a matching-decompilation run. First read work/gpt/PLAYBOOK.md and "
    "follow it exactly. It has the commands, the rules, the compiler facts and the report format.\n\n"
    "Then work this one function: {func} ({insns} instructions). An earlier helper got it to {best}% "
    "in work/gpt/{func}.c. Do NOT start from a fresh draft: start from that file. Run dk try on it to "
    "see the differences left, then fix them one idea at a time. Report MATCH only when dk try prints "
    "MATCH.{hints}\n\nDon't read other files or docs beyond what the playbook's commands show you. "
    "Your final message must be only the report line the playbook describes.\n")
LIMIT_RE = re.compile(r"rate.?limit|usage limit|too many requests|\b429\b", re.I)
# Codex features a headless decomp helper never uses, measured on Codex 0.162.1. Keep
# code_mode_host: newer models (gpt-6-luna) run every shell command through it.
LEAN_OFF = ("apps", "browser_annotation_api", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
            "computer_use", "daemon_auto_start", "goals", "guardian_approval", "hooks",
            "image_generation", "in_app_browser", "in_app_chat", "in_app_dictation", "in_app_local_automation",
            "in_app_updates", "in_app_voice", "mentions_v2", "multi_agent", "plugin_sharing", "plugins",
            "realtime_conversation", "remote_plugin", "skill_mcp_dependency_install", "skill_search",
            "tool_suggest", "view_image", "workspace_dependencies", "worktrees")


def lookalikes(p: Project, func: str, threshold: float = 0.85, limit: int = 3) -> list[tuple[str, float]]:
    """Decompiled functions that coddog finds similar to func, best first."""
    coddog = TC / "bin/coddog"
    if not coddog.exists():
        return []
    r = run([coddog, "match", func, "-t", str(threshold)], cwd=p.root, check=False)
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*([\d.]+)% - (\w+) \(decompiled\)", line)
        if m and m.group(2) != func:
            out.append((m.group(2), float(m.group(1))))
    return out[:limit]


def hint_text(p: Project, func: str) -> str:
    """A prompt paragraph naming finished look-alikes and the unoptimised case."""
    parts = []
    found = lookalikes(p, func)
    if found:
        names = ", ".join(f"{n} ({pct:.0f}% similar)" for n, pct in found)
        parts.append(f"Finished functions that look like it: {names}. Read their C first "
                     f"(`grep -n -A40 \"{found[0][0]}(\" src/*.c`): the same code shape usually matches.")
    if looks_unoptimised(p, func):
        parts.append(f"It was built without optimisation: keep `{O0_PRAGMA}` before it and `{O0_RESET}` after it.")
    return ("\n\n" + " ".join(parts)) if parts else ""


def codex_usage(log: Path) -> dict:
    """Token counts summed over a Codex --json log."""
    tot: dict = {}
    for line in log.read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        for k, v in (e.get("usage") or {}).items():
            if isinstance(v, int):
                tot[k] = tot.get(k, 0) + v
    return tot


class Adopted:
    """A helper an earlier runner started: watched and stopped by pid alone."""

    def __init__(self, pid: int):
        self.pid = pid

    def poll(self):
        return None if Path(f"/proc/{self.pid}").exists() else 0

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass


def grind_accept(p: Project, funcs: list[str], src_dir: Path | None = None) -> dict[str, str]:
    """Accept claimed matches together: one full build for the batch, halving it
    when the build breaks. Work files come from src_dir (default work/gpt).
    Returns {func: "" if accepted, else why not}."""
    with project_lock(p):
        return accept_claims(p, funcs, src_dir or p.root / "work/gpt")


def accept_claims(p: Project, funcs: list[str], src_dir: Path) -> dict[str, str]:
    rem = p.remaining()
    out: dict[str, str] = {}
    items: dict[str, str] = {}
    for f in funcs:
        path = src_dir / f"{f}.c"
        if f not in rem:
            out[f] = "no longer INCLUDE_ASM in src/"
            continue
        if not path.exists():
            out[f] = "work file missing"
            continue
        text = path.read_text()
        try:
            body, decls, local = split_work(f, text)
        except SystemExit:
            out[f] = "no definition in the work file"
            continue
        sig = body.split("{", 1)[0]
        if "M2C_" in body + local or any("M2C_" in d for d in decls):
            out[f] = "M2C_ placeholders left"
        elif not sig.lstrip().startswith("static") and \
                any(re.search(rf"\b{re.escape(t)}\b", sig) for t in local_types(local)):
            out[f] = "signature uses a type declared only in its file"
        else:
            items[f] = text
    if items:
        why: dict[str, str] = {}
        done = accept_many(p, items, why)
        if done:
            git(p, "add", "src", "include")
            git(p, "commit", "-qm", f"Match {len(done)} functions (dk grind)\n\n" + "\n".join(sorted(done)))
        for f in items:
            out[f] = "" if f in done else why.get(f, "the full build no longer matches")
    return out


def cmd_accept_many(a):
    """Accept many claimed matches from one folder with one full build."""
    p = Project.find()
    results = grind_accept(p, a.funcs, Path(a.dir).resolve())
    for f, why in sorted(results.items()):
        print(f"{f}: {'REJECTED: ' + why if why else 'ACCEPTED'}")
    cmd_progress(a)


def cmd_grind(a):
    """Run GPT helpers (Codex in its Linux sandbox, one function per helper, many
    at once) over the smallest unfinished functions. Claimed matches are accepted
    in batches (one full byte-exact build each); everything else is recorded in
    work/grind/state.json for a second pass. Stop gently: touch work/grind/STOP"""
    p = Project.find()
    codex = TC / "codex/bin/codex"
    if not codex.exists():
        die("Codex isn't in the toolchain; see setup/toolchain.sh")
    if not (p.root / "work/gpt/PLAYBOOK.md").exists():
        die("work/gpt/PLAYBOOK.md is missing: the helpers read it first")
    g = p.root / "work/grind"
    logs = g / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (g / "STOP").unlink(missing_ok=True)
    state_path = g / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    log = open(g / "grind.log", "a")

    def note(msg: str):
        line = f"{time.strftime('%m-%d %H:%M:%S')} {msg}"
        print(line, flush=True)
        log.write(line + "\n")
        log.flush()

    def verdict_of(f: str) -> tuple[str, str]:
        report = logs / f"{f}.txt"
        text = report.read_text(errors="replace") if report.exists() else ""
        m = re.search(rf"^\s*{f}\s*\|\s*([^|\n]+)", text, re.M)
        return (m.group(1).strip() if m else ""), text

    lock = threading.Lock()  # the accept thread records results too

    def record(f: str, s: dict, msg: str):
        with lock:
            state[f] = s
            write_atomic(state_path, json.dumps(state, indent=1) + "\n")
            note(f"{f} ({s.get('insns', '?')}) {s['status']}: {msg}")

    # A restart adopts what the last run left: helpers still working (a runner stopped
    # mid-run leaves them going) and the reports written since that run started.
    last_start = 0.0
    if (g / "grind.log").exists():
        for ln in (g / "grind.log").read_text().splitlines():
            if " start: " in ln:
                last_start = time.mktime(time.strptime(f"{time.localtime().tm_year}-{ln[:14]}", "%Y-%m-%d %H:%M:%S"))
    live: dict[str, int] = {}
    for d in Path("/proc").iterdir():
        try:
            argv = (d / "cmdline").read_bytes().split(b"\0") if d.name.isdigit() else []
        except OSError:
            continue
        if argv and argv[0].endswith(b"/bin/codex"):
            m = re.search(rb"work this one function: (func_\w+)", b" ".join(argv))
            if m:
                live[m.group(1).decode()] = int(d.name)
    finished: list[tuple] = []
    todo: list[tuple[int, str]] = []
    skip = skip_tags(p)
    triage_path = g / "triage.json"
    triage = json.loads(triage_path.read_text()) if triage_path.exists() else {}
    errors: dict[str, str] = {}
    best: dict[str, int] = {}  # --near: how close the earlier file got
    for f in p.remaining():
        st = state.get(f, {})
        if f in live:
            continue
        report = logs / f"{f}.txt"
        if verdict_of(f)[0] and (st.get("status") in ("running", "matched") or st.get("status") in (None, "error")
                                 and report.stat().st_mtime >= last_start):
            finished.append((f, st.get("insns") or tags_for(p, f)[0], st.get("minutes", 0), False))
            continue
        near = (a.near and st.get("status") == "miss" and st.get("best", 0) >= a.near
                and (p.root / f"work/gpt/{f}.c").exists())
        if near:
            best[f] = st.get("best", 0)
        elif a.retry:
            # Only clashes a helper can fix in its own file: a byte change elsewhere needs a person.
            t = triage.get(f, {})
            if st.get("status") != a.retry or t.get("kind") == "bytes":
                continue
            errors[f] = "\n".join(ln.strip("# ") for ln in t.get("errors", []) if ln.strip("# -"))[:1500]
        elif st.get("status") not in (None, "running", "matched", "error"):
            continue
        n, tags = tags_for(p, f)
        if not skip & set(tags) and (near or a.min <= n <= a.max):
            todo.append((n, f))
    todo.sort(key=lambda t: (-best.get(t[1], 0), t[0]))  # near misses first, closest first; then smallest
    if a.limit:
        todo = todo[:a.limit]
    env = dict(os.environ, CODEX_HOME=str(TC / "codex-home"))
    running: dict[str, tuple] = {f: (Adopted(pid), time.time(), state.get(f, {}).get("insns") or tags_for(p, f)[0], None)
                                 for f, pid in live.items()}
    pause_until = 0.0
    start = time.time()
    model = ["-c", f'model="{a.model}"'] if a.model else []
    # The npm launcher keeps a node process (~85 MB) beside every helper; run the binary it wraps.
    codex = next((TC / "codex/lib").glob("**/x86_64-unknown-linux-musl/bin/codex"), codex)
    model += [x for f in LEAN_OFF for x in ("-c", f"features.{f}=false")]

    def workers() -> int:
        """Helpers to keep running; work/grind/WORKERS changes it during a run."""
        try:
            return int((g / "WORKERS").read_text())
        except (OSError, ValueError):
            return a.workers

    def launch():
        if a.minutes and time.time() - start > a.minutes * 60:
            return
        while todo and not (g / "STOP").exists() and len(running) < workers() and time.time() >= pause_until:
            n, f = todo.pop(0)
            (logs / f"{f}.txt").unlink(missing_ok=True)
            out = open(logs / f"{f}.jsonl", "w")
            if f in errors:
                prompt = RETRY_PROMPT.format(func=f, insns=n, errors=errors[f] or "(no details recorded)",
                                             hints=hint_text(p, f))
            elif f in best:
                prompt = NEAR_PROMPT.format(func=f, insns=n, best=best[f], hints=hint_text(p, f))
            else:
                prompt = GRIND_PROMPT.format(func=f, insns=n, hints=hint_text(p, f))
            cmd = [codex, "exec", *model, "-c", f'model_reasoning_effort="{a.effort}"', "-s", "workspace-write",
                   "--skip-git-repo-check", "--json", "-o", logs / f"{f}.txt", prompt]
            # Own session: a helper outlives its runner (WSL ends the runner's session with it),
            # so a restarted runner can adopt it.
            proc = subprocess.Popen([str(c) for c in cmd], cwd=p.root, env=env, start_new_session=True,
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
            running[f] = (proc, time.time(), n, out)
            with lock:
                # Keep the mark of a fresh-chat continuation, or every close miss gets fresh chats forever.
                state[f] = {"insns": n, "status": "running", **({"continued": True} if state.get(f, {}).get("continued") else {})}

    pending: list[str] = []
    accepter: threading.Thread | None = None

    def accept_batch(batch: list[str]):
        for f, why in grind_accept(p, batch).items():
            s = {**state[f], "status": "rejected" if why else "accepted"}
            if why:
                s["error"] = why
            record(f, s, why or "MATCH")

    note(f"start: {len(todo)} functions ({a.min}-{a.max} instructions), {len(finished)} reports to adopt, "
         f"{workers()} helpers, model {a.model or 'from codex-home'}, effort {a.effort}"
         + (f", {a.minutes} min" if a.minutes else ""))
    while True:
        busy = accepter is not None and accepter.is_alive()
        over = a.minutes and time.time() - start > a.minutes * 60
        if not running and not finished and not pending and not busy and ((g / "STOP").exists() or not todo or over):
            break
        launch()
        for f, (proc, t0, n, out) in list(running.items()):
            timed_out = time.time() - t0 > a.timeout * 60
            # After the time box, helpers get a few minutes' grace, then stop (status "error": retried next run).
            boxed = over and time.time() - start > (a.minutes + a.grace) * 60
            if proc.poll() is None:
                if timed_out or boxed:
                    proc.kill()
                continue
            if out:
                out.close()
            del running[f]
            finished.append((f, n, round((time.time() - t0) / 60, 1), timed_out))
        matches = []
        for f, n, minutes, timed_out in finished:
            verdict, text = verdict_of(f)
            s = {"insns": n, "minutes": minutes, "report": text.strip()[:300], **codex_usage(logs / f"{f}.jsonl")}
            if state.get(f, {}).get("continued"):
                s["continued"] = True
            if verdict.startswith("MATCH"):
                with lock:
                    state[f] = {**s, "status": "matched"}
                matches.append(f)
            elif verdict:
                pct = re.search(r"(\d+)%", verdict)
                got = int(pct.group(1)) if pct else 0
                status = "blocked" if verdict.lower().startswith("blocked") else "miss"
                # A long chat gets worse at the end: one fresh chat continues a close miss from its file.
                # 100% without a match is a clash outside the file: a fresh chat can't fix that.
                again = (status == "miss" and a.cont and a.cont <= got < 100 and not s.get("continued")
                         and (p.root / f"work/gpt/{f}.c").exists())
                record(f, {**s, "status": status, "best": got, **({"continued": True} if again else {})}, verdict)
                if again:
                    best[f] = got
                    todo.insert(0, (n, f))
                    note(f"{f}: a fresh chat continues from its {got}% file")
            elif LIMIT_RE.search(tail := (logs / f"{f}.jsonl").read_text(errors="replace")[-4000:]):
                todo.insert(0, (n, f))
                pause_until = time.time() + a.pause * 60
                note(f"{f}: GPT usage limit hit; no new helpers for {a.pause} min")
            elif "at capacity" in tail:
                todo.append((n, f))  # OpenAI's side was busy: the function waits for another turn
                note(f"{f}: model at capacity; queued again")
            else:
                record(f, {**s, "status": "timeout" if timed_out else "error"}, text.strip()[:80])
        finished.clear()
        pending += matches
        # Builds run beside the helpers, one batch at a time, so no helper waits for one.
        if pending and (accepter is None or not accepter.is_alive()):
            accepter = threading.Thread(target=accept_batch, args=(pending[:],))
            accepter.start()
            pending.clear()
        time.sleep(5)
    if accepter is not None:
        accepter.join()
    counts = Counter(v["status"] for v in state.values())
    note("done: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    cmd_progress(a)


ARG_REGS = {4: 0, 5: 1, 6: 2, 7: 3, 8: 4, 9: 5, 10: 6, 11: 7}  # a0-a3, t0-t3 (EABI)
ASM_WORD_RE = re.compile(r"/\* [0-9A-F]+ ([0-9A-F]{8}) ([0-9A-F]{8}) \*/")
# any function name, real or func_<address> (the callers keep the names they know)
CALL_RE = re.compile(r"\b(?!(?:if|while|for|switch|return|sizeof)\b)([A-Za-z_]\w*)\s*\(")
DECL_PREFIX_RE = re.compile(r"\s*(?:extern\s+|static\s+)?[A-Za-z_][\w\s\*]*[\s\*]")
TYPEDEF_BLOCK_RE = re.compile(r"^typedef\s+(?:struct|union|enum)\b[^{;]*\{", re.M)
TYPEDEF_LINE_RE = re.compile(r"^typedef\s+[^{;]+?\b(\w+)\s*(?:\[[^\]]*\]\s*)*;", re.M)
EXTERN_RE = re.compile(r"^\s*extern\s+([^;()]+?)\s*\b(D_[0-9A-F]+)\b([^;()]*);", re.M)
BLOCK_PROTO_RE = re.compile(r"^(\s+)(?:extern\s+)?(?!return\b)([A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\(([^;{}()]*)\))\s*;[ \t]*\n", re.M)


def params_read(p: Project, func: str) -> int:
    """Lower bound on a function's integer parameters: one past the highest
    argument register (a0-a3, t0-t3) its code reads before writing it."""
    path = next(p.root.glob(f"asm/**/{func}.s"), None)
    if path is None:
        return 0
    written: set[int] = set()
    top = 0
    for m in ASM_WORD_RE.finditer(path.read_text()):
        word = int.from_bytes(bytes.fromhex(m.group(2)), "little")
        ins = rabbitizer.Instruction(word, int(m.group(1), 16), p.category())
        for reads, field in ((ins.readsRs, "rs"), (ins.readsRt, "rt"), (ins.readsRd, "rd")):
            if reads():
                reg = getattr(ins, field).value
                if reg in ARG_REGS and reg not in written:
                    top = max(top, ARG_REGS[reg] + 1)
        for writes, field in ((ins.modifiesRs, "rs"), (ins.modifiesRt, "rt"), (ins.modifiesRd, "rd")):
            if writes():
                written.add(getattr(ins, field).value)
    return top


def call_sites(text: str) -> list[tuple[str, int, int]]:
    """(callee, line, argument count) for every call of a func_ in C text;
    declarations and definitions are skipped."""
    out = []
    for m in CALL_RE.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        before = text[start:m.start()]
        if DECL_PREFIX_RE.fullmatch(before) and not re.search(r"\breturn\s*$", before):
            continue
        i, depth, commas = m.end(), 1, 0
        while i < len(text) and depth:
            c = text[i]
            depth += (c == "(") - (c == ")")
            commas += c == "," and depth == 1
            i += 1
        inner = text[m.end():i - 1].strip()
        out.append((m.group(1), text.count("\n", 0, m.start()) + 1, 0 if inner in ("", "void") else commas + 1))
    return out


def param_types(params: str) -> str:
    """Parameter list with the names dropped: 's32 a, void *p' -> 's32,void*'.
    An empty list (unprototyped) stays distinct from (void)."""
    if not params.strip():
        return "?"
    out = []
    for prm in params.split(","):
        t = " ".join(prm.replace("*", " * ").split())
        parts = t.split(" ")
        if len(parts) > 1 and re.fullmatch(r"[A-Za-z_]\w*", parts[-1]) and parts[-1] not in ("int", "char", "long", "short"):
            parts = parts[:-1]
        out.append("".join(parts))
    return ",".join(x for x in out if x not in ("", "void"))


def typedef_blocks(text: str) -> list[tuple[str, str]]:
    """(name, full text) of each top-level typedef in C text."""
    out = []
    for m in TYPEDEF_BLOCK_RE.finditer(text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            depth += (text[i] == "{") - (text[i] == "}")
            i += 1
            if depth == 0:
                break
        end = text.find(";", i)
        name = re.search(r"(\w+)\s*$", text[i:end])
        if name:
            out.append((name.group(1), text[m.start():end + 1]))
    for m in TYPEDEF_LINE_RE.finditer(text):
        out.append((m.group(1), m.group(0)))
    return out


ARG_REG_LIST = [4, 5, 6, 7, 8, 9, 10, 11]


def split_params(params: str) -> list[str]:
    """Top-level comma split of a parameter or argument list."""
    out, depth, cur = [], 0, ""
    for c in params:
        depth += (c in "([{") - (c in ")]}")
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return [x for x in out if x != "void"]


def asm_calls(p: Project, func: str, callee: str) -> list[tuple[int, set[int]]]:
    """For each jal from func to callee: (index, registers written from the
    start of func up to and including the call's delay slot)."""
    path = next(p.root.glob(f"asm/**/{func}.s"), None)
    if path is None:
        return []
    target = int(callee[5:], 16)
    insns = []
    for m in ASM_WORD_RE.finditer(path.read_text()):
        word = int.from_bytes(bytes.fromhex(m.group(2)), "little")
        insns.append(rabbitizer.Instruction(word, int(m.group(1), 16), p.category()))
    out, written = [], set()
    for i, ins in enumerate(insns):
        for writes, field in ((ins.modifiesRs, "rs"), (ins.modifiesRt, "rt"), (ins.modifiesRd, "rd")):
            if writes():
                written.add(getattr(ins, field).value)
        if ins.isJumpWithAddress() and ins.getInstrIndexAsVram() == target:
            slot = set(written)
            if i + 1 < len(insns):
                d = insns[i + 1]
                for writes, field in ((d.modifiesRs, "rs"), (d.modifiesRt, "rt"), (d.modifiesRd, "rd")):
                    if writes():
                        slot.add(getattr(d, field).value)
            out.append((i, slot))
    return out


def call_fixes(p: Project, files: dict[Path, str], rem: set[str]) -> list[tuple[str, list]]:
    """Old calls that pass fewer arguments than the callee reads, where the
    missing ones are the caller's own parameters passed straight through (the
    caller's code never touches those registers before the call). One fix unit
    per callee: every short call to it, plus its game.h guess widened to match.
    Returns (description, [(file, old text, new text), ...]) units."""
    units: dict[str, list] = {}
    notes: dict[str, list] = {}
    need_cache: dict[str, int] = {}
    blocked: set[str] = set()
    for path, text in files.items():
        defs = [(m.group(2), m.group(1)) for m in DEF_RE.finditer(text)]
        spans = {name: function_span(text, name) for name, _ in defs}
        sigs = dict(defs)
        for m in CALL_RE.finditer(text):
            callee = m.group(1)
            if callee not in rem:
                continue
            start = text.rfind("\n", 0, m.start()) + 1
            before = text[start:m.start()]
            if DECL_PREFIX_RE.fullmatch(before) and not re.search(r"\breturn\s*$", before):
                continue
            i, depth = m.end(), 1
            while i < len(text) and depth:
                depth += (text[i] == "(") - (text[i] == ")")
                i += 1
            args = split_params(text[m.end():i - 1])
            if callee not in need_cache:
                need_cache[callee] = params_read(p, callee)
            need = need_cache[callee]
            if len(args) >= need:
                continue
            owner = next((n for n, sp in spans.items() if sp and sp[0] <= m.start() < sp[1]), None)
            owner_calls = [x for x in CALL_RE.finditer(text[spans[owner][0]:spans[owner][1]])
                           if x.group(1) == callee] if owner else []
            jals = asm_calls(p, owner, callee) if owner else []
            if len(owner_calls) != 1 or len(jals) != 1:
                blocked.add(callee)
                continue
            written = jals[0][1]
            sig = sigs[owner]
            owner_params = split_params(sig[sig.index("(") + 1:sig.rindex(")")])
            extra = []
            for k in range(len(args), need):
                name = re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*$", owner_params[k]) if k < len(owner_params) else None
                if ARG_REG_LIST[k] in written or not name:
                    break
                extra.append(name.group(1))
            if len(args) + len(extra) < need:
                blocked.add(callee)
                continue
            old = text[start:i]
            if text.count(old) != 1:
                blocked.add(callee)
                continue
            new = text[start:m.end()] + ", ".join(args + extra) + ")"
            units.setdefault(callee, []).append((path, old, new))
            notes.setdefault(callee, []).append(owner)
    game_h = p.root / "include/game.h"
    header = game_h.read_text()
    out = []
    for callee, edits in sorted(units.items()):
        if callee in blocked:
            continue  # some call to it can't be repaired this way: leave them all as they are
        line = next((ln for ln in header.splitlines() if decl_name(ln) == callee and "(" in ln), None)
        if line:
            params = split_params(line[line.index("(") + 1:line.rindex(")")])
            if len(params) < need_cache[callee]:
                widened = line[:line.index("(") + 1] + ", ".join(
                    params + ["s32"] * (need_cache[callee] - len(params))) + line[line.rindex(")"):]
                edits = edits + [(game_h, line, widened)]
        out.append((f"{len(notes[callee])} caller(s) now pass their parameters on to {callee}", edits))
    return out


def definition_fixes(p: Project, files: dict[Path, str]) -> list[tuple[str, list]]:
    """Decompiled functions that take fewer parameters than their callers pass
    (m2c drops unused ones): add the missing ones back, unused."""
    calls: dict[str, int] = {}
    for text in files.values():
        for callee, _, n in call_sites(text):
            calls[callee] = max(calls.get(callee, 0), n)
    out = []
    for path, text in files.items():
        for m in DEF_RE.finditer(text):
            name, sig = m.group(2), m.group(1)
            params = split_params(sig[sig.index("(") + 1:sig.rindex(")")])
            want = calls.get(name, 0)
            if want <= len(params) or any("..." in x for x in params) or text.count(sig) != 1:
                continue
            extra = [f"s32 unused{k}" for k in range(len(params), want)]
            new = sig[:sig.index("(") + 1] + ", ".join(params + extra) + sig[sig.rindex(")"):]
            out.append((f"{name} takes {want} parameters, as its callers pass", [(path, sig, new)]))
    return out


def apply_text_fixes(p: Project, units: list) -> tuple[list, list]:
    """Apply (description, [(file, old, new), ...]) units in batches, keeping
    those the full build accepts (halving a batch that breaks it). Edits are
    found by their text, so earlier kept units can't shift later ones."""
    kept, dropped = [], []

    def attempt(batch):
        if not batch:
            return
        old: dict[Path, str] = {}
        live = []
        for unit in batch:
            texts = {f: old.get(f) or f.read_text() for f, _, _ in unit[1]}
            for f in texts:
                old.setdefault(f, f.read_text())
            current = {f: f.read_text() for f in texts}
            ok = True
            for f, o, n in unit[1]:
                if current[f].count(o) != 1:
                    ok = False
                    break
                current[f] = current[f].replace(o, n, 1)
            if not ok:
                dropped.append((unit, "its code moved"))
                continue
            for f, t in current.items():
                write_atomic(f, t)
            live.append(unit)
        if not live:
            return
        for path, text in sync_headers(p).items():
            old.setdefault(path, text)
        r = clean_check(p)
        if r.returncode == 0:
            kept.extend(live)
            return
        restore(old)
        sync_headers(p)
        if len(live) == 1:
            dropped.append((live[0], build_failure(p, r)))
            return
        attempt(live[:len(live) // 2])
        attempt(live[len(live) // 2:])

    attempt(units)
    return kept, dropped


def cmd_protos(a):
    """Report the declarations that will break future matches, and (--fix) clean
    the safe ones: old calls passing fewer arguments than the function reads,
    globals declared with different types, type names defined in two files,
    and block-scope prototypes that only repeat functions.h."""
    p = Project.find()
    rem = set(p.remaining())
    files = {f: f.read_text() for f in p.c_files()}
    exact = {name: sig for name, sig in defined_functions(p).items()}

    short_calls = []
    by_callee: dict[str, list] = {}
    for f, text in files.items():
        for callee, line, n in call_sites(text):
            by_callee.setdefault(callee, []).append((f.name, line, n))
    for callee, sites in sorted(by_callee.items()):
        if callee not in rem:
            continue
        need = params_read(p, callee)
        for fname, line, n in sites:
            if n < need:
                short_calls.append(f"{fname}:{line}: calls {callee} with {n} argument(s); its code reads {need}")

    externs: dict[str, set] = {}
    for path in [*files, p.root / "include/game.h", p.root / "include/structs.h"]:
        text = files.get(path) or path.read_text()
        for m in EXTERN_RE.finditer(text):
            externs.setdefault(m.group(2), set()).add(" ".join((m.group(1) + m.group(3)).split()))
    clashing_globals = {k: v for k, v in externs.items() if len(v) > 1}

    typedefs: dict[str, list] = {}
    for f, text in files.items():
        for name, body in typedef_blocks(text):
            typedefs.setdefault(name, []).append((f, body))
    dup_types = {k: v for k, v in typedefs.items() if len({f for f, _ in v}) > 1}
    same_types = {k: v for k, v in dup_types.items() if len({" ".join(b.split()) for _, b in v}) == 1}

    redundant = []
    for f, text in files.items():
        for m in BLOCK_PROTO_RE.finditer(text):
            name, params = m.group(3), m.group(4)
            sig = exact.get(name)
            if sig and param_types(params) == param_types(sig[sig.index("(") + 1:sig.rindex(")")]) \
                    and m.group(2).split(name)[0].split() == sig.split(name)[0].split():
                redundant.append((f, m.group(0)))

    print(f"{len(short_calls)} old calls pass fewer arguments than the callee's code reads "
          f"(they block that callee's match):")
    for s in short_calls[:a.n]:
        print("  " + s)
    print(f"{len(clashing_globals)} globals are declared with different types:")
    for k, v in sorted(clashing_globals.items())[:a.n]:
        print(f"  {k}: " + " | ".join(sorted(v)))
    print(f"{len(dup_types)} type names are defined in more than one file "
          f"({len(same_types)} identical, safe to share):")
    for k, v in sorted(dup_types.items())[:a.n]:
        print(f"  {k}: " + ", ".join(sorted({f.name for f, _ in v})) + (" (identical)" if k in same_types else ""))
    print(f"{len(redundant)} block-scope prototypes only repeat functions.h")
    if not a.fix:
        return

    with project_lock(p):
        notes = []
        if same_types or redundant:
            old = {f: t for f, t in files.items()}
            structs = p.root / "include/structs.h"
            old[structs] = structs.read_text()
            new = dict(files)
            for f, block in redundant:
                new[f] = new[f].replace(block, "", 1)
            shared = []
            for name, v in sorted(same_types.items()):
                for f, body in v:
                    new[f] = new[f].replace(body + "\n", "", 1).replace(body, "", 1)
                shared.append(v[0][1])
            for f, text in new.items():
                if text != files[f]:
                    write_atomic(f, text)
            if shared:
                head, _, tail = old[structs].rpartition("#endif")
                write_atomic(structs, head + "\n\n".join(shared) + "\n\n#endif" + tail)
            r = clean_check(p)
            if r.returncode:
                restore(old)
                print(f"sharing types / dropping repeated prototypes broke the build "
                      f"({build_failure(p, r)}); skipped")
            else:
                notes.append(f"{len(shared)} types shared, {len(redundant)} repeated prototypes dropped")
        files = {f: f.read_text() for f in p.c_files()}
        kept, dropped = apply_text_fixes(p, definition_fixes(p, files))
        files = {f: f.read_text() for f in p.c_files()}
        kept2, dropped2 = apply_text_fixes(p, call_fixes(p, files, set(p.remaining())))
        for unit in kept + kept2:
            print("  fixed  " + unit[0])
        for unit, why in dropped + dropped2:
            print(f"  left   {unit[0]}  ({why})")
        if kept:
            notes.append(f"{len(kept)} definitions take the parameters their callers pass")
        if kept2:
            notes.append(f"{len(kept2)} calls pass their caller's parameters through")
        if notes:
            git(p, "add", "src", "include")
            git(p, "commit", "-qm", "dk protos --fix: " + "; ".join(notes))
    print("fixed: " + ("; ".join(notes) if notes else "nothing") + ". Build still exact.")


def twin_sources(p: Project, twin: str) -> list[str]:
    """Candidate C for a finished function: the work files it may have been
    accepted from, then its definition cut from src/ (enough when it uses only
    shared declarations)."""
    out = []
    for folder in (p.root / "work/gpt", p.root / "work", *(Path(d) for d in p.cfg.get("work_dirs", []))):
        path = folder / f"{twin}.c"
        if path.exists():
            text = path.read_text()
            if re.search(rf"^[A-Za-z_][\w \t\*]*?\b{twin}\s*\(", text, re.M) and "M2C_" not in text:
                out.append(text)
    for cfile in p.c_files():
        text = cfile.read_text()
        span = function_span(text, twin)
        if span:
            out.append('#include "common.h"\n#include "game.h"\n\n' + text[span[0]:span[1]] + "\n")
            break
    return list(dict.fromkeys(out))


def cmd_twins(a):
    """Match functions that are exact copies of finished ones: take the twin's
    C, rename it, and keep it when dk try and the full build agree."""
    p = Project.find()
    skip = skip_tags(p)
    out_dir = p.root / "work/twins"
    out_dir.mkdir(parents=True, exist_ok=True)
    good: dict[str, str] = {}
    tried = 0
    for f in sorted(p.remaining()):
        n, tags = tags_for(p, f)
        if skip & set(tags) or n < a.min:
            continue
        twins = [t for t, pct in lookalikes(p, f, threshold=0.999, limit=5) if pct >= 99.99]
        for twin, text in ((t, x) for t in twins for x in twin_sources(p, t)):
            tried += 1
            renamed = re.sub(rf"\b{twin}\b", f, text).replace(f"_{twin[5:]}", f"_{f[5:]}")
            path = out_dir / f"{f}.c"
            path.write_text(renamed)
            res, _ = try_func(p, f, path)
            if res and res[0] == res[1] == res[2]:
                own, other, _ = context_check(p, f, renamed)
                if not own and not other:
                    good[f] = renamed
                    print(f"{f}: copy of {twin} matches", flush=True)
                    break
    print(f"{len(good)} of {tried} twin copies match; accepting")
    if good:
        results = grind_accept(p, list(good), out_dir)
        print(f"accepted {sum(1 for w in results.values() if not w)}, "
              f"rejected {sum(1 for w in results.values() if w)}")
    cmd_progress(a)


def cmd_libs(a):
    p = Project.find()
    if p.ps2:
        die("no PS2 library signatures yet")
    img = load_image((p.root / "assets" / p.cfg["exe"]).read_bytes())
    sdk, names, objs = scan_psyq(img, p.cfg["text_start"], p.cfg["data_start"])
    print(f"PsyQ SDK looks like {sdk[0]}.{sdk[1:]}: {objs} library objects, {len(names)} functions")
    if len(p.remaining()) < p.cfg.get("functions", 0):
        print("functions were already decompiled, so names were not changed (renames would break src/)")
        return
    write_symbols(p, names)
    r = p.make("split")
    r = p.make("check") if not r.returncode else r
    print("renamed and re-split; build matches" if not r.returncode else (r.stdout + r.stderr)[-2000:])


def cmd_compiler(a):
    p = Project.find()
    picks = []
    for f in p.remaining():
        n, tags = tags_for(p, f)
        if a.min <= n <= a.max and not {"switch", "data", "lib", "handwritten", "vu0", "patched"} & set(tags):
            picks.append((n, f))
    picks = [f for _, f in sorted(picks)[:a.n]]
    if not picks:
        die("no small, simple functions to test with")
    drafts = {}
    for f in picks:
        path = p.root / "build/compiler" / f"{f}.c"
        path.parent.mkdir(parents=True, exist_ok=True)
        draft = m2c(p, f, strict=False)
        if draft is not None and "Decompilation failure" not in draft:
            path.write_text(draft)
            drafts[f] = path
    versions = a.gcc.split(",") if a.gcc else sorted(
        d.name for d in (TC / ("ee-gcc" if p.ps2 else "gcc")).iterdir() if d.is_dir())
    if p.ps2 and not a.gcc:
        versions += [f"mwcps2-{d.name}" for d in sorted((TC / "mwcps2").iterdir())]
    flag_sets = a.cflags.split(";") if a.cflags else [p.cfg["cflags"]]
    gs = [a.g] if a.g is not None else [0, 8] if p.cfg["g"] or p.ps2 else [0]
    print(f"testing {len(drafts)} small functions (m2c drafts, no hand edits)")
    results = []
    for v in versions:
        for g in gs:
            for fl in flag_sets:
                exact = insns = total = 0
                for f, path in drafts.items():
                    res, _ = try_func(p, f, path, gcc=v, g=g, cflags=fl)
                    if res is None:
                        continue
                    matched, nt, nc, _, _ = res
                    exact += matched == nt == nc
                    insns += matched
                    total += nt
                results.append((exact, insns, v, g, fl))
                print(f"  {v:22s} -G{g} {fl:12s}: {exact}/{len(drafts)} exact, {insns}/{total} instructions",
                      flush=True)
    top = max((r[0], r[1]) for r in results)
    tied = [(v, g, fl) for e, i, v, g, fl in results if (e, i) == top]
    current = (p.cfg["gcc"], p.cfg["g"], p.cfg["cflags"])
    best = current if current in tied else tied[0]
    if len({v for v, _, _ in tied}) > 1:
        print(f"tie between {', '.join(sorted({v for v, _, _ in tied}))}: these functions are too simple "
              f"to tell them apart (try bigger ones: --min 25 --max 120)")
    print(f"best: {best[0]} -G{best[1]} {best[2]}")
    if a.save and best != current:
        p.cfg["gcc"], p.cfg["g"], p.cfg["cflags"] = best
        p.save()
        print("saved to dk.json")


def main():
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet when piped into head/awk
    ap = argparse.ArgumentParser(prog="dk", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("new")
    s.add_argument("name")
    s.add_argument("disc")
    s.add_argument("--dir")
    s.set_defaults(fn=cmd_new)
    sub.add_parser("build").set_defaults(fn=cmd_build)
    sub.add_parser("progress").set_defaults(fn=cmd_progress)
    s = sub.add_parser("next")
    s.add_argument("-n", type=int, default=15)
    s.add_argument("--all", action="store_true", help="include switch tables, library and handwritten code")
    s.add_argument("--near", action="store_true", help="closest m2c drafts first (after dk harvest)")
    s.set_defaults(fn=cmd_next)
    s = sub.add_parser("draft")
    s.add_argument("func")
    s.set_defaults(fn=cmd_draft)
    for name, fn in (("try", cmd_try), ("accept", cmd_accept)):
        s = sub.add_parser(name)
        s.add_argument("func")
        s.add_argument("file", nargs="?")
        if name == "try":
            s.add_argument("--gcc")
            s.add_argument("--g", type=int)
            s.add_argument("--cflags")
            s.add_argument("--lines", type=int, default=30)
            s.add_argument("--no-context", action="store_true",
                           help="skip compiling the match inside its real file")
        s.set_defaults(fn=fn)
    s = sub.add_parser("revert")
    s.add_argument("func")
    s.add_argument("--why", default="")
    s.set_defaults(fn=cmd_revert)
    s = sub.add_parser("perm")
    s.add_argument("func")
    s.add_argument("file", nargs="?")
    s.add_argument("--minutes", type=int, default=5)
    s.add_argument("--jobs", type=int, default=int(CORES))
    s.set_defaults(fn=cmd_perm)
    s = sub.add_parser("ghidra")
    s.add_argument("funcs", nargs="+")
    s.add_argument("--refresh", action="store_true",
                   help="re-teach Ghidra the C's types and prototypes even if nothing changed")
    s.set_defaults(fn=cmd_ghidra)
    s = sub.add_parser("twins")
    s.add_argument("--min", type=int, default=4, help="smallest function size in instructions")
    s.set_defaults(fn=cmd_twins)
    s = sub.add_parser("protos")
    s.add_argument("--fix", action="store_true", help="share identical types and drop repeated prototypes")
    s.add_argument("-n", type=int, default=25, help="how many of each problem to list")
    s.set_defaults(fn=cmd_protos)
    s = sub.add_parser("accept-many")
    s.add_argument("--dir", required=True, help="folder holding the F.c work files")
    s.add_argument("funcs", nargs="+")
    s.set_defaults(fn=cmd_accept_many)
    s = sub.add_parser("grind")
    s.add_argument("--workers", type=int, default=10, help="GPT helpers running at once")
    s.add_argument("--min", type=int, default=8, help="smallest function size in instructions")
    s.add_argument("--max", type=int, default=100, help="largest function size in instructions")
    s.add_argument("--limit", type=int, default=0, help="stop after this many functions (0 = all)")
    s.add_argument("--effort", default="max", help="GPT reasoning effort")
    s.add_argument("--model", help="GPT model (default: the one in codex-home/config.toml)")
    s.add_argument("--near", type=int, default=0, help="also finish earlier misses that reached this %% or "
                   "more, any size, ahead of the rest and closest first, starting from their work files "
                   "(--max 0: only those)")
    s.add_argument("--continue", dest="cont", type=int, default=0, help="a miss that reached this %% or more "
                   "gets one fresh chat that continues from its work file")
    s.add_argument("--minutes", type=int, default=0, help="launch no new helpers after this many minutes")
    s.add_argument("--grace", type=int, default=5, help="minutes running helpers get after --minutes")
    s.add_argument("--timeout", type=int, default=45, help="minutes before a helper is stopped")
    s.add_argument("--pause", type=int, default=15, help="minutes to wait after a usage-limit error")
    s.add_argument("--retry", help="re-run functions with this status (rejected), starting from their "
                   "work file and the build errors in work/grind/triage.json")
    s.set_defaults(fn=cmd_grind)
    s = sub.add_parser("harvest")
    s.add_argument("-n", type=int, default=200, help="how many of the smallest functions to try")
    s.add_argument("--max", type=int, default=200, help="largest function size in instructions")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_harvest)
    sub.add_parser("libs").set_defaults(fn=cmd_libs)
    s = sub.add_parser("compiler")
    s.add_argument("-n", type=int, default=12)
    s.add_argument("--min", type=int, default=6, help="smallest function size in instructions")
    s.add_argument("--max", type=int, default=40, help="largest function size in instructions")
    s.add_argument("--gcc", help="comma-separated versions to test (default: all)")
    s.add_argument("--cflags", help="semicolon-separated flag sets to test (default: the project's)")
    s.add_argument("--g", type=int)
    s.add_argument("--save", action="store_true")
    s.set_defaults(fn=cmd_compiler)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
