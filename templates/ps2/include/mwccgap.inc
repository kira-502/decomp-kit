# mwccgap pastes this in front of every function it assembles. splat's asm is
# hand-scheduled, so the assembler must not reorder or use $at on its own.
.include "macro.inc"
.set noat
.set noreorder
