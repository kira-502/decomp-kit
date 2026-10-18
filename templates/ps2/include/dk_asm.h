#ifndef DK_ASM_H
#define DK_ASM_H

/* INCLUDE_ASM keeps a not-yet-decompiled function as its original assembly so
 * the build stays byte-identical. Metrowerks builds go through mwccgap, which
 * swaps these lines for the assembled functions itself, so the macros are
 * empty there. GCC builds splice the asm in with file-scope asm, which GCC
 * 2.9x/3.x emit in source order. */
#if defined(__MWERKS__) || defined(M2CTX) || defined(PERMUTER)
#define INCLUDE_ASM(FOLDER, NAME)
#define INCLUDE_RODATA(FOLDER, NAME)
#else
#define INCLUDE_ASM(FOLDER, NAME)                                       \
    __asm__(".section .text\n"                                          \
            "\t.set noat\n"                                             \
            "\t.set noreorder\n"                                        \
            "\t.include \"" FOLDER "/" #NAME ".s\"\n"                   \
            "\t.set reorder\n"                                          \
            "\t.set at\n")
#define INCLUDE_RODATA(FOLDER, NAME)                    \
    __asm__(".section .rodata\n"                        \
            "\t.include \"" FOLDER "/" #NAME ".s\"\n"   \
            ".section .text")
__asm__(".include \"include/macro.inc\"\n");
#endif

#endif
