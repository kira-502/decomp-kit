# decomp-kit

Tools for starting and grinding matching decompilations of PlayStation 1 and 2 games:
C source that compiles back into the exact bytes of the original executable.

- Kit source: this folder (`dk`, `dk.py`, `dklib/`, `templates/`, `setup/`).
- Toolchain: WSL `Ubuntu-24.04`, `~/decomp/toolchain` (2.1 GB). It has GNU binutils for
  mipsel, every PSX GCC from decompals/old-gcc (2.5.7 to 2.95.2), GNU as 2.7 and 2.8.1,
  the PS2 EE GCC and Metrowerks builds, splat (pinned), spimdisasm, m2c, maspsx,
  mwccgap, asm-differ, decomp-permuter, objdiff-cli, lab313ru's PsyQ signatures, and:
  - coddog: finds near-identical functions (`coddog cluster`, `coddog match F`).
    It reads the `decomp.yaml` that dk writes.
  - Ghidra (headless, Java 21) with the Emotion Engine extension: `dk ghidra F`.
  - ccc's `stdump`: shows whether a PS2 ELF still carries debug symbols. Check this
    before picking a game, since symbols make a decomp much faster.
  - Mizuchi: a Claude + m2c + permuter + objdiff matching pipeline, kept for the
    grinder. It needs a Claude login in WSL before it can run.
- Reference decomps, kept to read and never built: `~/decomp/ref/`.
  - `dark-cloud`: Metrowerks 2.3.3, 100% matched, with overlays and a PC port.
  - `extermination`: Metrowerks 2.3.3 at -O4,p.
  - `gt4`: Claude agents do the matching; see its `tools/autoloop.py` and skill.
  - `elf2mwo`: writes the MWo3 overlay format.
- Games: `~/decomp/games/<name>`, one git repo each.

## Setup (once per machine)

From Windows, `MSYS_NO_PATHCONV=1` stops Git Bash from mangling `/mnt/c/...` paths.

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -e bash "/mnt/c/path/to/decomp-kit/setup/toolchain.sh"
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -e bash "/mnt/c/path/to/decomp-kit/setup/selftest-pe.sh"
```

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -e bash -lc 'ln -sf "/mnt/c/path/to/decomp-kit/dk" ~/decomp/toolchain/bin/dk'
```

The self-test rebuilds the finished Parasite Eve decomp with the shared toolchain and
checks the retail SHA-1. It took 36 s on 2026-10-10.

## Working a game

Run these inside WSL after `. ~/decomp/toolchain/env.sh`:

| step | command | what it does |
|---|---|---|
| start | `dk new ape-escape "/path/to/your/Ape Escape (USA).cue"` | Pulls the boot exe off the disc, guesses where code, rodata and data sit, names PsyQ library functions from signatures, repairs switch cases that splat split off, then builds and proves a byte match. |
| compiler | `dk compiler --min 25 --max 120 --gcc 2.7.2,2.8.1 --save` | Compiles m2c drafts of small functions with each GCC and keeps the one that matches most. Tiny functions can't tell versions apart. |
| free wins | `dk harvest -n 5000 --max 400` | Accepts every function whose plain m2c draft already matches. No hand edits; the full build checks each batch. Records how close every other draft got. |
| pick | `dk next --near` / `dk next` | Lists the closest drafts first, or the smallest functions. Library, hand-written, vector-unit (`vu0`), patched and (until rodata is attached) switch functions are skipped; `--all` shows them. `patched` = code that borrows another function's registers or stack frame (patched into the game after it was built), plus the functions that jump into or out of it: no C compiles to it alone. |
| twins | `dk twins` | Copies the C of a finished function into an unfinished one that coddog finds identical (100%), renamed, and keeps it when `dk try`, the fit check and the full build agree. Most coddog twins differ in data addresses or offsets, so expect few. |
| work | `dk draft F`, edit `work/F.c`, `dk try F` | Prints a compact instruction diff of the original against yours. |
| look-alikes | `coddog match F -t 0.9` | Lists functions that look like F. If one is already C, copy its shape. |
| second view | `dk ghidra F` (PS2) | Ghidra's C for F. Ghidra knows callers, strings and Sony system-call names that m2c doesn't. The first run analyses the program (about 2 min); after that it takes 5 s. Each run first teaches Ghidra what the C knows when that changed (every type, each global's merged struct views, the prototypes of decompiled functions, func_/D_ names, the bss block): about 5 s more; `--refresh` forces it. |
| last mile | `dk perm F --minutes 5` | Runs decomp-permuter on all cores and saves the best result to `work/F.perm.c`. |
| grind | `dk grind --workers 30 --max 100` | Runs GPT helpers (Codex inside Linux, sandboxed to the project, one function each) over the smallest unfinished functions. Every MATCH goes through `dk accept` at once; misses, blocked ones and rejections go to `work/grind/state.json` for a second pass. Stop gently with `touch work/grind/STOP`. The helpers read `work/gpt/PLAYBOOK.md`. |
| fit check | (inside `dk try`) | After a standalone match, `dk try` places the work file the way `dk accept` will, in a scratch copy of src/ and include/, and compiles every C file it touches or that calls it. `CLASH` = lines from the work file clash (fix the file); `BLOCKED BY CALLER` = older code in the game doesn't compile with it. `--no-context` skips it. |
| declarations | `dk protos [--fix]` | Reports calls passing fewer arguments than the callee's code reads (found from its asm), globals declared with different types, type names defined twice, and block-scope prototypes that repeat functions.h. `--fix` repairs what is safe, in units checked by full builds: definitions get back the unused parameters their callers pass, calls pass their caller's parameters through when the asm shows those registers untouched, game.h guesses are widened to match, and repeated prototypes are dropped. |
| keep | `dk accept F` | Swaps the INCLUDE_ASM for the C, rebuilds, checks the SHA-1, then commits. Nothing changes if the build stops matching. |
| status | `dk progress`, `dk build` | |

## How a project is laid out

- `config/main.yaml`: the splat config that `dk new` wrote. You can edit it by hand
  (to split files, for example), and `make split` regenerates the asm from it.
- `src/main.c`: one translation unit for all code. Unmatched functions are `INCLUDE_ASM`.
- Rodata belongs to main and travels with each function (`migrate_rodata_to_functions`),
  so switch tables and strings come with their function. PsyQ links rodata either before
  the code (Parasite Eve) or after it (Ape Escape); `section_order` follows the game.
- `include/game.h`: externs gathered from accepted drafts. `include/functions.h`:
  the exact prototype of every decompiled function, rewritten on every accept.
- `include/structs.h`: struct types and globals that more than one function uses,
  edited by hand. When two drafts each invent a type for the same global, the build
  fails with "redeclared". Merge them into one type here.
- `config.mk` (written from `dk.json`): `DK_GCC`, `DK_CFLAGS`, `DK_G`, `DK_MASPSX`.

## Traps already hit

- splat skips some functions on a re-split when `src/main.c` exists. The fix is
  `disassemble_all: True`, which is now in the template.
- PsyQ signature labels include IDA local names (`loc_`, `text_`...). Declaring those
  as functions splits real functions apart, so they are filtered out.
- A switch case ending in `jr $ra` looks like the end of a function. dk sets the true
  function `size:` in `symbol_addrs.txt` for every function whose jump table points
  past that end.
- A decl that m2c guessed can clash with the real definition. dk drops guessed
  prototypes for decompiled names and keeps the exact ones in `functions.h`.
- A re-split files decompiled functions' asm under `asm/**/matchings/`. Padding used to
  look only in `nonmatchings/`, which broke every re-split after the first accept.
  `pad_functions.py` now looks in both places, and `dk revert` re-splits when it needs to.
- A splat upgrade can change the split. splat is pinned in `setup/toolchain.sh`, so bump
  the pin only after `make split && make check` still matches.

## PS2

`dk new` reads a PS2 ELF the same way it reads a PS1 EXE. It rebuilds the whole
file, keeping the ELF headers before and after the loaded block as binary blobs.

- Compilers: 11 EE GCC builds (Sony's Linux builds, plus SN Systems' Windows
  builds run under wibo) and 26 Metrowerks CodeWarrior builds (`mwcps2-*`). One
  more GCC build (3.2-030210-beta2) needs cygwin and doesn't run.
  `dk compiler` tries all of them.
- Metrowerks builds go through mwccgap, which compiles the C and splices each
  `INCLUDE_ASM` function back in. `tools/pad_functions.py` pads every decompiled
  function to its original size. Metrowerks gives each function its own section,
  but splat's SUBALIGN(4) is still needed for the GNU-as objects.
- The code is split into C files of about 50 functions (`chunks` in dk.json).
  Builds run in parallel and an accept rebuilds one file: a full Duelists of the
  Roses build takes 3 s. Functions over 1500 instructions stay plain asm files,
  because Metrowerks takes minutes on mwccgap's placeholder for them.
- `tools/fix_asm.py` runs after every split:
  - VU0 macro instructions (and any other mnemonic GNU as rejects) become `.word`.
  - Cross-file jump targets get global aliases.
  - Alternate entries get local twins.
  - j/jal or address loads of local labels become `.word`.
- `merge_sizes` rejoins functions that splat cut apart; the evidence is a jump
  into the middle of a neighbour. Cuts only show once the code is in separate
  files, so `dk new` splits, rejoins and repeats.
- mwccgap traps: it reads C from stdin whenever stdin isn't a terminal, so cc.sh
  passes `< /dev/null`. The setup script patches its unguarded rodata index.

Duelists of the Roses (SLUS_205.15) is Metrowerks 2.3.3 at `-O4,p -sdatathreshold 0`.
Two quirks gave it away: it zeroes registers with `paddub`, and every GCC build
matched 0 of 16 functions while Metrowerks matched 12. The game's own label,
"MW MIPS C Compiler (2.3.1.01)", is the backend version. Both public builds
(2.3-991202 and 2.3.3-000906) print that same label, so it is not a missing third
build. Dark Cloud's decomp reached 100% on 2.3.3. `-O4,p` keeps every match that
`-O3` had and fixes short loops: func_001DEF20 went from 79% to 94%.

## Not built yet

- Overlays: code loaded from disc archives. This is per game, and needs the loader's
  addresses. Duelists of the Roses has 833 overlay slots.
- Splitting `main.c` back into the original files.
- Matching PsyQ library C from donor projects such as psyz and sotn psxsdk, and
  signatures for PS2 libraries.
- Duplicates across games. coddog's `compare2` and `compare-n` can do it, but every
  project in the comparison has to be built, which needs that game's disc.
- Switch-table rodata for PS2.
- `dk ghidra` for PS1. It needs a PS-X EXE loader in Ghidra (lab313ru's ghidra_psx_ldr).

## Your disc

dk never ships or uploads game data. `dk new` reads your own disc image and writes its path to `dk.local.json`
in the project (ignored by git); `dk.json` only holds a placeholder. Moving the image later: edit `dk.local.json`.

## Licence

CC0 1.0 (public domain dedication): see [LICENSE](LICENSE). It covers this kit only, not any game or SDK.
