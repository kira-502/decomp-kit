#!/usr/bin/env python3
"""Point each decompiled function's switch jump table at the game's own table.

Metrowerks gives every function its own .rodata section for its jump table and
loads the table through a local symbol (`@9`). In the game those tables sit in
the data blob (asm/data/data.data.s, labels jtbl_XXXXXXXX) as plain addresses,
which stay right as long as the code matches. So the compiled table is not
needed: each table symbol becomes an absolute symbol named after the original
table (taken, in order, from the function's asm file), and the compiled table's
section is renamed so the linker script's /DISCARD/ drops it.
Usage: jtbl_fix.py object.o   (run from the project root, after pad_functions.py)"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(os.environ["DK_TOOLCHAIN"]) / "src/mwccgap"))
from mwccgap.elf import Elf, TextSection  # noqa: E402

JTBL_RE = re.compile(r"%hi\((jtbl_[0-9A-Fa-f]{8})\)")
R_MIPS_HI16 = 5
SHN_ABS = 0xFFF1
SHF_ALLOC = 0x2
DROPPED = ".jtbl_compiled"

path = Path(sys.argv[1])
elf = Elf(path.read_bytes())
names = {}
for symbol in elf.symtab.symbols:
    if symbol.type == 2 and not symbol.name.endswith(".NON_MATCHING"):  # STT_FUNC
        names.setdefault(symbol.st_shndx, symbol.name)

changed = False
for record in elf.get_relocations():
    target = record.sh_info
    func = names.get(target)
    if func is None or not isinstance(elf.sections[target], TextSection):
        continue
    tables = []  # table symbol indexes, in order of first use
    for reloc in sorted(record.relocations, key=lambda r: r.r_offset):
        if reloc.reloc_type != R_MIPS_HI16:
            continue
        symbol = elf.symtab.symbols[reloc.symbol_index]
        shndx = symbol.st_shndx
        if (symbol.bind == 0 and symbol.name.startswith("@") and 0 < shndx < len(elf.sections)
                and elf.sections[shndx].name == ".rodata" and reloc.symbol_index not in tables):
            tables.append(reloc.symbol_index)
    if not tables:
        continue
    asm = next(Path("asm").glob(f"**/{func}.s"), None)
    if asm is None:  # not a game function (a scratch file): nothing to point at
        continue
    originals = list(dict.fromkeys(JTBL_RE.findall(asm.read_text())))
    if len(originals) != len(tables):
        sys.exit(f"jtbl_fix: {func} has {len(tables)} switch table(s), its asm uses {len(originals)}")
    for index, original in zip(tables, originals):
        symbol = elf.symtab.symbols[index]
        section = elf.sections[symbol.st_shndx]
        section.sh_flags &= ~SHF_ALLOC
        section.sh_name = elf.add_sh_symbol(DROPPED)
        section.name = DROPPED
        symbol.name = original
        symbol.st_name = elf.strtab.add_symbol(original)
        symbol.st_shndx = SHN_ABS
        symbol.st_value = int(original[5:], 16)
        changed = True
if changed:
    path.write_bytes(elf.pack())
