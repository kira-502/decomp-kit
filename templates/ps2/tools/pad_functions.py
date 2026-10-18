#!/usr/bin/env python3
"""Pad each decompiled function's section to the space the original function
took up, so the next function lands where it did in the game.

Metrowerks puts every function in its own aligned .text section, but splat's
linker script places sections with SUBALIGN(4), which the GNU-as objects need.
So the padding has to live inside the section. The original space is the
function's asm file from splat, including the padding nops after it.
Usage: pad_functions.py object.o   (run from the project root)"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(os.environ["DK_TOOLCHAIN"]) / "src/mwccgap"))
from mwccgap.elf import Elf, TextSection  # noqa: E402

WORD_RE = re.compile(r"^\s*/\* [0-9A-F]+ [0-9A-F]{8} [0-9A-F]{8} \*/", re.M)

path = Path(sys.argv[1])
elf = Elf(path.read_bytes())
names = {}
for symbol in elf.symtab.symbols:
    if symbol.type == 2 and not symbol.name.endswith(".NON_MATCHING"):  # STT_FUNC
        names.setdefault(symbol.st_shndx, symbol.name)
for index, section in enumerate(elf.sections):
    name = names.get(index)
    if not isinstance(section, TextSection) or name is None:
        continue
    # A split made after the function was decompiled files it under matchings/.
    asm = next(Path("asm").glob(f"**/{name}.s"), None)
    if asm is None:
        continue
    slot = 4 * len(WORD_RE.findall(asm.read_text()))
    if len(section.data) < slot:
        section.data += bytes(slot - len(section.data))
path.write_bytes(elf.pack())
