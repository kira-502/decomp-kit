"""What the C already knows, as one header for Ghidra (`dk ghidra`).

Collects every type (the shared headers, plus file-scope and block-scope types in
src/), every view of each D_ global (its declarations and the struct types it is
cast to), the prototype of each decompiled func_, and the game's data labels.
ghidra/ApplyTypes.java reads the result into the Ghidra project, so Ghidra's view
shows our names, struct fields and argument counts.
"""
import hashlib
import json
import pickle
import re
import subprocess
from pathlib import Path

from pycparser import c_ast, c_generator, c_parser

BASIC = {"s8", "u8", "s16", "u16", "s32", "u32", "s64", "u64", "f32", "f64", "char", "int",
         "short", "long", "float", "double", "unsigned", "signed", "void", "__int128"}
GLOBAL = re.compile(r"D_[0-9A-F]+$")
FUNC = re.compile(r"func_[0-9A-F]{8}$")
SEP = "/*@*/"  # ApplyTypes.java parses each piece on its own, so a bad piece costs only itself
CACHE_VERSION = 4


def _strip_asm(text: str) -> str:
    """Drop `__asm__ [volatile] ( ... )` (balanced, strings skipped): pycparser has no asm."""
    out, i = [], 0
    for m in re.finditer(r"__asm__\s*(?:volatile|__volatile__)?\s*\(", text):
        if m.start() < i:
            continue
        out.append(text[i:m.start()])
        j, depth, in_str = m.end(), 1, False
        while j < len(text) and depth:
            c = text[j]
            if in_str:
                if c == "\\":
                    j += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        i = j
    out.append(text[i:])
    return "".join(out)


def preprocess(cpp: list, include: Path, path: Path) -> str:
    # No -P: the line markers tell pycparser which file each declaration came from.
    cpp = [x for x in cpp if x != "-P"]
    r = subprocess.run([*cpp, "-DM2CTX", "-D__attribute__(x)=", "-D__inline=inline", "-D__inline__=inline",
                        "-D__extension__=", "-D__volatile__=volatile", "-D__signed__=signed",
                        "-I", str(include), str(path)], capture_output=True, text=True)
    text = _strip_asm(r.stdout)
    return re.sub(r"^\s*#\s*pragma.*$", "", text, flags=re.M)


def _type_names(node) -> set:
    """Typedef and struct names a declaration's type refers to."""
    names = set()

    class V(c_ast.NodeVisitor):
        def visit_IdentifierType(self, n):
            names.update(x for x in n.names if x not in BASIC)

        def visit_Struct(self, n):
            if n.name:
                names.add("struct " + n.name)
            self.generic_visit(n)

        def visit_Union(self, n):
            if n.name:
                names.add("union " + n.name)
            self.generic_visit(n)

    V().visit(node)
    return names


def _rank_global(decl: c_ast.Decl) -> int:
    t = decl.type
    if isinstance(t, c_ast.ArrayDecl):
        inner = t.type
        if isinstance(inner, c_ast.TypeDecl) and isinstance(inner.type, c_ast.IdentifierType) \
                and set(inner.type.names) <= {"u8", "s8", "char", "unsigned", "signed"} and t.dim is None:
            return 0  # `u8 D[]`: a byte view for casts, says nothing
    if _type_names(t):
        return 3
    return 2 if isinstance(t, (c_ast.ArrayDecl, c_ast.PtrDecl)) else 1


class Collector(c_ast.NodeVisitor):
    """What one translation unit says; merge() folds units together in order."""

    def __init__(self, only_file=None):
        self.gen = c_generator.CGenerator()
        self.only_file = only_file  # visit only declarations from this file (not its headers)
        self.types = {}      # name -> declaration text, first wins
        self.order = []
        self.globals = {}    # name -> {declaration text: rank}
        self.funcs = {}      # name -> declaration text (definitions only)
        self.casts = {}      # global -> struct typedef names it is cast to: `(T *)D_X`
        self.in_func = False

    def visit_FileAST(self, n):
        for ext in n.ext:
            if self.only_file is None or (ext.coord and ext.coord.file == self.only_file):
                self.visit(ext)

    def _add_type(self, name, text):
        if name not in self.types:
            self.types[name] = text
            self.order.append(name)

    def visit_Typedef(self, n):
        if n.name not in BASIC:  # its text holds any struct it defines: don't visit inside
            self._add_type(n.name, self.gen.visit(n) + ";")

    def _tagged(self, n, kind):
        if n.name and getattr(n, "values" if kind == "enum" else "decls", None) is not None:
            self._add_type(f"{kind} {n.name}", self.gen.visit(n) + ";")
        self.generic_visit(n)

    def visit_Struct(self, n):
        self._tagged(n, "struct")

    def visit_Union(self, n):
        self._tagged(n, "union")

    def visit_Enum(self, n):
        self._tagged(n, "enum")

    def visit_FuncDef(self, n):
        name = n.decl.name or ""
        if isinstance(n.decl.type, c_ast.FuncDecl):  # every name: write_inputs keeps func_ ones
            d = c_ast.Decl(name, [], [], [], [], n.decl.type, None, None)
            self.funcs[name] = self.gen.visit(d) + ";"
        self.visit(n.decl)
        self.in_func = True
        self.visit(n.body)
        self.in_func = False

    def visit_Decl(self, n):
        name = n.name or ""
        if GLOBAL.match(name) and not isinstance(n.type, c_ast.FuncDecl) \
                and (not self.in_func or "extern" in n.storage):
            rank = _rank_global(n)
            if rank > 0:
                d = c_ast.Decl(name, [], [], [], [], n.type, None, None)
                views = self.globals.setdefault(name, {})
                text = self.gen.visit(d) + ";"
                views[text] = max(views.get(text, 0), rank)
        self.generic_visit(n)

    def visit_Cast(self, n):
        e = n.expr
        if isinstance(e, c_ast.UnaryOp) and e.op == "&":
            e = e.expr
        t = n.to_type.type
        if isinstance(e, c_ast.ID) and GLOBAL.match(e.name) and isinstance(t, c_ast.PtrDecl) \
                and isinstance(t.type, c_ast.TypeDecl) and isinstance(t.type.type, c_ast.IdentifierType):
            names = [x for x in t.type.type.names if x not in BASIC]
            if names:
                self.casts.setdefault(e.name, set()).add(names[0])
        self.generic_visit(n)

    def state(self):
        return self.types, self.order, self.globals, self.funcs, self.casts

    def merge(self, state):
        types, order, globals_, funcs, casts = state
        for name in order:
            self._add_type(name, types[name])
        for name, views in globals_.items():
            mine = self.globals.setdefault(name, {})
            for text, rank in views.items():
                mine[text] = max(mine.get(text, 0), rank)
        self.funcs.update(funcs)
        for name, cands in casts.items():
            self.casts.setdefault(name, set()).update(cands)

    def resolve_casts(self):
        """Struct views cast onto a global (`(State *)D_X` with `u8 D_X[]`) are views of it
        too; ApplyTypes.java merges every struct view of a global into one struct."""
        for name, cands in self.casts.items():
            for t in sorted(cands):
                if self.types.get(t, "").lstrip().startswith("typedef struct"):
                    self.globals.setdefault(name, {}).setdefault(f"{t} {name};", 2.5)

    def views(self, name) -> list:
        """A global's declarations, best first: rank, then the richer type."""
        v = self.globals[name]
        return sorted(v, key=lambda t: (-v[t], -len(self.types.get(t.split()[0], "")), t))


def collect(root: Path, cpp: list):
    """Headers first, then each src file's own declarations. A file's result is cached
    by its content, so a refresh after an accept parses only the changed files."""
    include = root / "include"
    parser = c_parser.CParser()
    cache_path = root / "build/ghidra/parse.cache"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        cache = pickle.loads(cache_path.read_bytes())
        if cache.get("version") != CACHE_VERSION:
            cache = {}
    except Exception:
        cache = {}
    new_cache: dict = {"version": CACHE_VERSION}
    col, failed = Collector(), []
    hdr = root / "build/ghidra/headers.c"
    hdr.write_text('#include "common.h"\n')
    files = [hdr] + sorted((root / "src").glob("main_*.c"))
    for path in files:
        key = hashlib.sha1(path.read_bytes()).hexdigest()
        hit = cache.get(str(path))
        if path != hdr and hit and hit[0] == key:
            state = hit[1]
        else:
            text = preprocess(cpp, include, path)
            try:
                ast = parser.parse(text, str(path))
            except Exception as e:  # pycparser's ParseError, or a lexer error
                failed.append(f"{path.name}: {e}")
                continue
            one = Collector(None if path == hdr else str(path))
            one.visit(ast)
            state = one.state()
        new_cache[str(path)] = (key, state)
        col.merge(state)
    hdr.unlink()
    cache_path.write_bytes(pickle.dumps(new_cache))
    col.resolve_casts()
    return col, failed


def labels(root: Path) -> dict:
    """D_ names with addresses: data labels, and the linker's undefined symbols."""
    out = {}
    for s in (root / "asm/data").glob("*.s"):
        for m in re.finditer(r"^\s*dlabel\s+(D_([0-9A-F]+))\s*$", s.read_text(), re.M):
            out[m.group(1)] = int(m.group(2), 16)
    for t in (root / "linker").glob("undefined_*_auto.txt"):
        for m in re.finditer(r"^(D_\w+)\s*=\s*(0x[0-9A-Fa-f]+);", t.read_text(), re.M):
            out[m.group(1)] = int(m.group(2), 16)
    return out


def jumptables(root: Path) -> list:
    """`JT <jump address> <case address>...` for each switch: a function's Nth `jr` (not $ra)
    goes with the Nth jump table its code loads (`%hi(jtbl_X)`), whose words are case addresses."""
    tables, cur = {}, None
    data = root / "asm/data/data.data.s"
    for line in data.read_text().splitlines() if data.exists() else []:
        m = re.match(r"\s*dlabel\s+(jtbl_[0-9A-F]+)", line)
        if m:
            cur = tables.setdefault(m.group(1), [])
        elif cur is not None and re.match(r"\s*enddlabel", line):
            cur = None
        elif cur is not None:
            w = re.search(r"\.word\s+0x([0-9A-Fa-f]+)", line)
            if w:
                cur.append(int(w.group(1), 16))
    cfg = json.loads((root / "dk.json").read_text())
    lo, hi = cfg["vram"], cfg.get("data_start", cfg["vram"] + cfg["size"])  # code: tables end in padding words
    out = []
    for s in (root / "asm").glob("**/*.s"):
        text = s.read_text()
        if "jtbl_" not in text or not (s.stem.startswith("func_") or "matchings" in s.parts
                                       or "nonmatchings" in s.parts):
            continue
        used = list(dict.fromkeys(re.findall(r"%hi\((jtbl_[0-9A-F]+)\)", text)))
        jumps = re.findall(r"/\*\s*[0-9A-F]+\s+([0-9A-F]{8})\s+[0-9A-F]{8}\s*\*/\s+jr\s+\$(?!ra\b)", text)
        if len(used) == len(jumps):
            out += [f"JT {j} " + " ".join(f"{t:08X}" for t in tables[u] if lo <= t < hi)
                    for j, u in zip(jumps, used) if tables.get(u)]
    return sorted(out)


def header_text(col: Collector) -> str:
    lines = ["/* dk ghidra: types, globals and prototypes from the C (generated) */\n"
             "typedef signed char s8; typedef unsigned char u8; typedef short s16;\n"
             "typedef unsigned short u16; typedef int s32; typedef unsigned int u32;\n"
             "typedef long long s64; typedef unsigned long long u64; typedef float f32;\n"
             "typedef struct { unsigned int w[4]; } __int128;"]
    lines += [col.types[n] for n in col.order]
    # Each view of a global as a typedef dk_G<k>_D_X (k = 0 is the best): CParser keeps a
    # typedef's whole declarator, arrays too.
    for n in sorted(col.globals):
        lines += ["typedef " + re.sub(rf"\b{n}\b", f"dk_G{k}_{n}", text, count=1)
                  for k, text in enumerate(col.views(n))]
    # Only decompiled functions: a caller's guess at an unfinished one is often worse than Ghidra's.
    lines += [col.funcs[n] for n in sorted(col.funcs)]
    return f"\n{SEP}\n".join(lines) + "\n"


def write_inputs(root: Path, cpp: list, out_dir: Path):
    """Write types.h and labels.txt for ApplyTypes.java; returns (summary, header text)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    col, failed = collect(root, cpp)
    # Ghidra names functions func_<address>: a function with a real name goes under its old name
    # (config/old_names.txt, `func_XXXXXXXX = RealName;`)
    old_path = root / "config/old_names.txt"
    old = {new: o for o, new in re.findall(r"^(func_[0-9A-F]{8}) = (\w+);", old_path.read_text(), re.M)} \
        if old_path.exists() else {}
    col.funcs = {old.get(n, n): re.sub(rf"\b{n}\b", old[n], d, count=1) if n in old else d
                 for n, d in col.funcs.items() if FUNC.match(old.get(n, n))}
    text = header_text(col)
    (out_dir / "types.h").write_text(text)
    (out_dir / "labels.txt").write_text(
        "".join(f"{n} {a:08X}\n" for n, a in sorted(labels(root).items(), key=lambda x: x[1]))
        + "".join(j + "\n" for j in jumptables(root)))
    summary = (f"{len(col.types)} types, {len(col.globals)} globals, {len(col.funcs)} prototypes"
               + (f"; {len(failed)} C files unreadable ({failed[0]})" if failed else ""))
    return summary, text


if __name__ == "__main__":
    import sys
    import time
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    t0 = time.time()
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "build/ghidra"
    summary, _ = write_inputs(root, ["cpp", "-nostdinc", "-undef", "-D__GNUC__=2", "-P"], out)
    print(f"{summary}, {time.time() - t0:.1f}s")
