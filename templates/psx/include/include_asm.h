#ifndef INCLUDE_ASM_H
#define INCLUDE_ASM_H

#if !defined(M2CTX) && !defined(PERMUTER)
/* Keeps a not-yet-decompiled function as its original assembly so the build
 * stays byte-identical. maspsx strips the wrapper function and keeps the asm. */
#define INCLUDE_ASM(FOLDER, NAME)                                       \
    void __maspsx_include_asm_hack_##NAME(void) {                       \
        __asm__(".text # maspsx-keep\n"                                 \
                "\t.align\t2 # maspsx-keep\n"                           \
                "\t.set\tnoreorder # maspsx-keep\n"                     \
                "\t.set\tnoat # maspsx-keep\n"                          \
                "\t.include \"" FOLDER "/" #NAME ".s\" # maspsx-keep\n" \
                "\t.set\treorder # maspsx-keep\n"                       \
                "\t.set\tat # maspsx-keep\n");                          \
    }
#define INCLUDE_RODATA(FOLDER, NAME)                    \
    __asm__(".section .rodata\n"                        \
            "\t.include \"" FOLDER "/" #NAME ".s\"\n"   \
            ".section .text")
__asm__(".include \"include/macro.inc\"\n");
#else
#define INCLUDE_ASM(FOLDER, NAME)
#define INCLUDE_RODATA(FOLDER, NAME)
#endif

#endif
