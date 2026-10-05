#!/usr/bin/env python3
"""
Generate Vector-Sharp Dark-Themed Terminal SVGs for Principles Labs (06-09)
Linux Kernel Hardening Lab
"""

import html
import os

OUTPUT_DIR = "docs/assets/images/principles"

def create_terminal_svg(
    title: str,
    lines: list,  # list of tuples: (line_type, text)
    width: int = 860,
    min_height: int = 0
) -> str:
    """
    line_type options:
      'prompt': terminal command line ($ cmd)
      'header': bright cyan/blue title or section
      'success': emerald green output
      'warning': amber yellow highlight
      'error': ruby red error output
      'dim': slate gray secondary info / comment
      'highlight': bold purple/accent
      'code': neutral white/slate code text
      'blank': empty spacing line
    """
    line_height = 20
    padding_top = 48  # Titlebar (36) + padding (12)
    padding_bottom = 20
    
    total_height = max(min_height, padding_top + len(lines) * line_height + padding_bottom)
    
    svg_lines = []
    svg_lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {total_height}" width="100%" height="{total_height}" style="background: transparent; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \'Liberation Mono\', monospace;">')
    svg_lines.append('  <defs>')
    svg_lines.append('    <linearGradient id="termGrad" x1="0%" y1="0%" x2="0%" y2="100%">')
    svg_lines.append('      <stop offset="0%" stop-color="#0f172a" />')
    svg_lines.append('      <stop offset="100%" stop-color="#0b1120" />')
    svg_lines.append('    </linearGradient>')
    svg_lines.append('    <filter id="shadow" x="-4%" y="-4%" width="108%" height="108%" filterUnits="userSpaceOnUse">')
    svg_lines.append('      <feDropShadow dx="0" dy="8" stdDeviation="16" flood-color="#000000" flood-opacity="0.5"/>')
    svg_lines.append('    </filter>')
    svg_lines.append('  </defs>')
    
    # Outer Card with Border & Shadow
    svg_lines.append(f'  <rect x="2" y="2" width="{width-4}" height="{total_height-4}" rx="12" fill="url(#termGrad)" stroke="#334155" stroke-width="1.5" filter="url(#shadow)"/>')
    
    # Titlebar Background
    svg_lines.append(f'  <path d="M 2 14 C 2 7.37 7.37 2 14 2 L {width-14} 2 C {width-7.37} 2 {width-2} 7.37 {width-2} 14 L {width-2} 36 L 2 36 Z" fill="#1e293b" />')
    svg_lines.append(f'  <line x1="2" y1="36" x2="{width-2}" y2="36" stroke="#334155" stroke-width="1" />')
    
    # Window Controls (Red, Yellow, Green)
    svg_lines.append('  <circle cx="22" cy="19" r="6" fill="#ef4444" />')
    svg_lines.append('  <circle cx="40" cy="19" r="6" fill="#f59e0b" />')
    svg_lines.append('  <circle cx="58" cy="19" r="6" fill="#10b981" />')
    
    # Title Text
    safe_title = html.escape(title)
    svg_lines.append(f'  <text x="{width/2}" y="23" text-anchor="middle" fill="#94a3b8" font-size="12" font-weight="500">{safe_title}</text>')
    
    # Terminal Lines
    current_y = padding_top + 14
    for ltype, text in lines:
        escaped = html.escape(text)
        if ltype == 'blank':
            current_y += line_height
            continue
            
        if ltype == 'prompt':
            # Highlight user prompt differently from command
            svg_lines.append(f'  <text x="24" y="{current_y}" font-size="12.5" xml:space="preserve">')
            svg_lines.append('    <tspan fill="#38bdf8" font-weight="bold">hardening-lab@linux</tspan>')
            svg_lines.append('    <tspan fill="#94a3b8">:</tspan>')
            svg_lines.append('    <tspan fill="#a855f7" font-weight="bold">~/principles</tspan>')
            svg_lines.append(f'    <tspan fill="#f1f5f9" font-weight="bold">$ {escaped}</tspan>')
            svg_lines.append('  </text>')
        elif ltype == 'header':
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#38bdf8" font-size="12" font-weight="bold" xml:space="preserve">{escaped}</text>')
        elif ltype == 'success':
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#34d399" font-size="12" xml:space="preserve">{escaped}</text>')
        elif ltype == 'warning':
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#fbbf24" font-size="12" xml:space="preserve">{escaped}</text>')
        elif ltype == 'error':
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#f87171" font-size="12" font-weight="bold" xml:space="preserve">{escaped}</text>')
        elif ltype == 'dim':
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#64748b" font-size="12" xml:space="preserve">{escaped}</text>')
        elif ltype == 'highlight':
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#c084fc" font-size="12" font-weight="bold" xml:space="preserve">{escaped}</text>')
        else: # 'code'
            svg_lines.append(f'  <text x="24" y="{current_y}" fill="#cbd5e1" font-size="12" xml:space="preserve">{escaped}</text>')
            
        current_y += line_height
        
    svg_lines.append('</svg>')
    return '\n'.join(svg_lines)

def build_all_svgs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # -------------------------------------------------------------
    # 1. 06-compiler-pipeline.svg
    # -------------------------------------------------------------
    lines_06_pipe = [
        ('prompt', 'gcc-13 -v --save-temps -O2 -g vault_core.c -o vault_core'),
        ('dim', '# [Pass 1] C Preprocessor (cpp / cc1 -E) -> Macro Expansion & Header Inlining'),
        ('code', '[+] Generated: vault_core.i (Preprocessed C source: 55,630 lines)'),
        ('dim', '# [Pass 2] Compiler Engine (cc1 -O2) -> AST, Optimization Passes, CodeGen'),
        ('code', '[+] Generated: vault_core.s (GNU x86_64 Assembly text: 541 lines)'),
        ('dim', '# [Pass 3] Assembler (as) -> Machine Code Translation to Relocatable ELF'),
        ('code', '[+] Generated: vault_core.o (ELF 64-bit Relocatable Object)'),
        ('dim', '# [Pass 4] Linker (collect2 / ld) -> Symbol Resolution & Segment Packaging'),
        ('success', '[+] Generated: vault_core   (ELF 64-bit PIE Executable)'),
        ('blank', ''),
        ('prompt', 'file vault_core.* vault_core'),
        ('highlight', 'vault_core.i: C source, Unicode text, UTF-8 text'),
        ('highlight', 'vault_core.s: assembler source, ASCII text'),
        ('header',    'vault_core.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), with debug_info'),
        ('success',   'vault_core:   ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked')
    ]
    with open(f"{OUTPUT_DIR}/06-compiler-pipeline.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Compiler Pipeline: Intermediate Files (gcc -v --save-temps)", lines_06_pipe, 840))

    # -------------------------------------------------------------
    # 2. 06-readelf-headers.svg
    # -------------------------------------------------------------
    lines_06_hdr = [
        ('prompt', 'readelf -h vault_core.o'),
        ('header', 'ELF Header (Relocatable Object File):'),
        ('code',   '  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00'),
        ('code',   '  Class:                             ELF64'),
        ('code',   '  Data:                              2\'s complement, little endian'),
        ('warning','  Type:                              REL (Relocatable file)'),
        ('dim',    '  Entry point address:               0x0  <-- [No entry point defined yet!]'),
        ('dim',    '  Start of program headers:          0 (bytes into file) <-- [No Program Headers!]'),
        ('code',   '  Start of section headers:          9816 (bytes into file)'),
        ('code',   '  Number of section headers:         24'),
        ('blank', ''),
        ('prompt', 'readelf -h vault_core'),
        ('header', 'ELF Header (Position-Independent Executable):'),
        ('code',   '  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00'),
        ('success','  Type:                              DYN (Position-Independent Executable file)'),
        ('success','  Entry point address:               0x1190  <-- [_start in .text]'),
        ('success','  Start of program headers:          64 (bytes into file)  <-- [13 Segments for Kernel Loader]'),
        ('code',   '  Start of section headers:          16832 (bytes into file)'),
        ('code',   '  Number of section headers:         39')
    ]
    with open(f"{OUTPUT_DIR}/06-readelf-headers.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("ELF Header Comparison: Relocatable (.o) vs Executable (readelf -h)", lines_06_hdr, 840))

    # -------------------------------------------------------------
    # 3. 06-readelf-symbols-opt.svg
    # -------------------------------------------------------------
    lines_06_sym = [
        ('prompt', 'readelf -s vault_core.o'),
        ('header', 'Symbol table \'.symtab\' contains 24 entries:'),
        ('dim',    '   Num:    Value          Size Type    Bind   Vis      Ndx Name'),
        ('code',   '    18: 0000000000000000   272 FUNC    GLOBAL DEFAULT    6 main'),
        ('warning','    19: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts  <-- [Compiler Optimization!]'),
        ('code',   '    20: 0000000000000000     8 OBJECT  GLOBAL DEFAULT    8 g_banner'),
        ('dim',    '    21: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __printf_chk'),
        ('highlight','  22: 0000000000000000   256 OBJECT  GLOBAL DEFAULT    3 g_session_token (Section 3: .bss)'),
        ('success','    23: 0000000000000000     4 OBJECT  GLOBAL DEFAULT    2 g_vault_status  (Section 2: .data)'),
        ('blank', ''),
        ('dim', '# Note: Compiler automatically converted printf("...\\n") with constant string to puts()!'),
        ('dim', '# Uninitialized g_session_token (256B) placed into .bss; initialized g_vault_status in .data.')
    ]
    with open(f"{OUTPUT_DIR}/06-readelf-symbols-opt.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Section & Symbol Table Analysis: puts Optimization (readelf -s)", lines_06_sym, 840))

    # -------------------------------------------------------------
    # 4. 07-symbol-conflict-error.svg
    # -------------------------------------------------------------
    lines_07_conflict = [
        ('prompt', 'gcc-13 auth_main.c token_validator.c token_conflict.c -o test_conflict'),
        ('error',  '/usr/bin/ld: /tmp/ccuiQshk.o: in function \'verify_auth_token\':'),
        ('error',  'token_conflict.c:(.text+0x0): multiple definition of \'verify_auth_token\';'),
        ('error',  '/tmp/ccDJYFSi.o:token_validator.c:(.text+0x0): first defined here'),
        ('error',  'collect2: error: ld returned 1 exit status'),
        ('blank', ''),
        ('dim', '# [Root Cause Analysis]'),
        ('warning','- Symbol: verify_auth_token (Type: FUNC, Bind: GLOBAL, Status: STRONG in both files)'),
        ('code',   '- Rule 1 of Linker Symbol Resolution: Multiple strong symbols cannot coexist!'),
        ('dim', '- Fix: Mark one implementation as static (LOCAL) or declare as __attribute__((weak)).')
    ]
    with open(f"{OUTPUT_DIR}/07-symbol-conflict-error.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Linker Error: Multiple Definition Conflict (Rule 1 Violation)", lines_07_conflict, 840))

    # -------------------------------------------------------------
    # 5. 07-symbol-local-error.svg
    # -------------------------------------------------------------
    lines_07_local = [
        ('prompt', 'gcc-13 auth_main.c token_local.c -o test_local'),
        ('error',  '/usr/bin/ld: /tmp/ccrYOTnt.o: in function \'main\':'),
        ('error',  'auth_main.c:(.text+0x82): undefined reference to \'g_auth_counter\''),
        ('error',  'collect2: error: ld returned 1 exit status'),
        ('blank', ''),
        ('prompt', 'readelf -s token_local.o | grep g_auth_counter'),
        ('warning','     4: 0000000000000000     4 OBJECT  LOCAL  DEFAULT    4 g_auth_counter'),
        ('blank', ''),
        ('dim', '# [Root Cause Analysis]'),
        ('dim', '- In token_local.c: declared as "static int g_auth_counter;"'),
        ('highlight','- LOCAL binding restricts visibility strictly to token_local.c translation unit.'),
        ('code',   '- auth_main.c declares "extern int g_auth_counter;", but linker cannot resolve it!')
    ]
    with open(f"{OUTPUT_DIR}/07-symbol-local-error.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Linker Error: Undefined Reference due to LOCAL Binding", lines_07_local, 840))

    # -------------------------------------------------------------
    # 6. 07-symbol-strip-verification.svg
    # -------------------------------------------------------------
    lines_07_strip = [
        ('prompt', 'readelf -S auth_demo | grep -E \'\\.symtab|\\.dynsym\''),
        ('success','  [ 6] .dynsym           DYNSYM           00000000000003d8  000003d8  (Dynamic Symbols)'),
        ('header', '  [28] .symtab           SYMTAB           0000000000000000  00003040  (Static Debug Symbols)'),
        ('blank', ''),
        ('prompt', 'strip --strip-all auth_demo -o auth_demo_stripped'),
        ('prompt', 'readelf -S auth_demo_stripped | grep -E \'\\.symtab|\\.dynsym\''),
        ('success','  [ 6] .dynsym           DYNSYM           00000000000003d8  000003d8  (Preserved!)'),
        ('dim',    '  # Note: .symtab is completely eliminated to reduce size and obfuscate binaries.'),
        ('blank', ''),
        ('prompt', './auth_demo_stripped'),
        ('success','[+] Token verification result : VALID (g_auth_counter=1)'),
        ('success','[+] Calling auth_event_logger : [DEFAULT-WEAK-LOGGER] Cycle completed'),
        ('dim',    '--> Binary executes flawlessly! Runtime loader relies strictly on .dynsym.')
    ]
    with open(f"{OUTPUT_DIR}/07-symbol-strip-verification.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Symbol Stripping: .symtab Removal vs .dynsym Retention", lines_07_strip, 840))

    # -------------------------------------------------------------
    # 7. 08-static-archive-readelf.svg
    # -------------------------------------------------------------
    lines_08_ar = [
        ('prompt', 'ar rcs libsecure.a crypto_mac.o token_validator.o'),
        ('prompt', 'ar -t libsecure.a'),
        ('code',   'crypto_mac.o'),
        ('code',   'token_validator.o'),
        ('blank', ''),
        ('prompt', 'readelf -s libsecure.a'),
        ('header', 'File: libsecure.a(crypto_mac.o)'),
        ('success','     3: 0000000000000000    54 FUNC    GLOBAL DEFAULT    1 compute_mac'),
        ('header', 'File: libsecure.a(token_validator.o)'),
        ('success','     3: 0000000000000000    68 FUNC    GLOBAL DEFAULT    1 validate_security_token'),
        ('blank', ''),
        ('dim', '# Static archive (.a) packages individual relocatable .o files into an indexed archive.'),
        ('dim', '# Linker extracts ONLY the member objects that resolve currently unsatisfied external symbols.')
    ]
    with open(f"{OUTPUT_DIR}/08-static-archive-readelf.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Static Archive: Member Inspection & Symbol Extraction (ar & readelf)", lines_08_ar, 840))

    # -------------------------------------------------------------
    # 8. 08-static-maps-comparison.svg
    # -------------------------------------------------------------
    lines_08_maps = [
        ('prompt', 'readelf -l secvault_static | grep -A 1 LOAD'),
        ('header', '  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000'),
        ('code',   '                 0x000000000001b448 0x000000000001b448  R      0x1000'),
        ('header', '  LOAD           0x000000000001c000 0x000000000041c000 0x000000000041c000'),
        ('code',   '                 0x000000000006f521 0x00000000006f521  R E    0x1000'),
        ('header', '  LOAD           0x000000000008c000 0x000000000048c000 0x000000000048c000'),
        ('code',   '                 0x0000000000024068 0x00000000000282b8  RW     0x1000'),
        ('blank', ''),
        ('prompt', 'cat /proc/$(pidof secvault_static)/maps'),
        ('success','00400000-0041c000 r--p 00000000 08:01 1234567    /secvault_static  <-- [LOAD 1: R--]'),
        ('success','0041c000-0048c000 r-xp 0001c000 08:01 1234567    /secvault_static  <-- [LOAD 2: R-X]'),
        ('success','0048c000-004b1000 rw-p 0008c000 08:01 1234567    /secvault_static  <-- [LOAD 3: RW-]'),
        ('dim',    '004b1000-004d4000 rw-p 00000000 00:00 0          [heap]'),
        ('dim',    '7ffdb4a1e000-7ffdb4a3f000 rw-p 00000000 00:00 0  [stack]')
    ]
    with open(f"{OUTPUT_DIR}/08-static-maps-comparison.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("PT_LOAD Segments vs /proc/<pid>/maps 1:1 Memory Mapping", lines_08_maps, 840))

    # -------------------------------------------------------------
    # 9. 09-gdb-lazy-binding-step1.svg
    # -------------------------------------------------------------
    lines_09_gdb1 = [
        ('prompt', 'gdb -q -nx ./secvault_dyn'),
        ('dim',    '(gdb) b main && run'),
        ('code',   'Breakpoint 1, main () at secvault_dyn.c:16'),
        ('blank', ''),
        ('header', '=== [Step 1: BEFORE 1st Call to verify_token] ==='),
        ('prompt', 'x/gx &verify_token@got.plt'),
        ('warning','0x555555558020 <verify_token@got.plt>:    0x0000555555555070'),
        ('blank', ''),
        ('prompt', 'x/2i 0x0000555555555070'),
        ('dim',    '   0x555555555070:  endbr64'),
        ('highlight',' 0x555555555074:  push   $0x4        <-- [Relocation Slot Index in .rela.plt]'),
        ('highlight',' 0x555555555079:  jmp    0x555555555020 <-- [.plt header: _dl_runtime_resolve]'),
        ('blank', ''),
        ('dim', '# Crucial Finding: GOT entry points BACK to .plt stub, NOT the shared library function!')
    ]
    with open(f"{OUTPUT_DIR}/09-gdb-lazy-binding-step1.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("GDB Tracing Lazy Binding [Step 1]: GOT Points to PLT Trampoline", lines_09_gdb1, 840))

    # -------------------------------------------------------------
    # 10. 09-gdb-lazy-binding-step2.svg
    # -------------------------------------------------------------
    lines_09_gdb2 = [
        ('prompt', 'continue  # (Executes 1st call to verify_token, invoking dynamic linker)'),
        ('code',   '[*] [Call 1] Invoking verify_token() for the first time...'),
        ('success','[+] [Call 1 Result] AUTHORIZED'),
        ('code',   'Breakpoint 2, main () at secvault_dyn.c:28 (Before Call 2)'),
        ('blank', ''),
        ('header', '=== [Step 2: AFTER 1st Call to verify_token] ==='),
        ('prompt', 'x/gx &verify_token@got.plt'),
        ('success','0x555555558020 <verify_token@got.plt>:    0x00007ffff7fb9119'),
        ('blank', ''),
        ('prompt', 'info symbol 0x00007ffff7fb9119'),
        ('success','verify_token in section .text of ./libsecure.so'),
        ('blank', ''),
        ('dim', '# Crucial Finding: _dl_runtime_resolve updated GOT with actual virtual address!'),
        ('dim', '# 2nd call to verify_token will branch DIRECTLY to 0x7ffff7fb9119 without linker intervention.')
    ]
    with open(f"{OUTPUT_DIR}/09-gdb-lazy-binding-step2.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("GDB Tracing Lazy Binding [Step 2]: GOT Overwritten with Target Function", lines_09_gdb2, 840))

    # -------------------------------------------------------------
    # 11. 09-relocation-byte-analysis.svg
    # -------------------------------------------------------------
    lines_09_reloc = [
        ('prompt', 'readelf -r secvault_dyn'),
        ('header', 'Relocation section \'.rela.plt\' at offset 0x668 contains 5 entries:'),
        ('dim',    '  Offset          Info           Type           Sym. Value        Sym. Name + Addend'),
        ('code',   '  000000004000  000100000007 R_X86_64_JUMP_SLOT 0000000000000000 puts@GLIBC_2.2.5 + 0'),
        ('code',   '  000000004008  000200000007 R_X86_64_JUMP_SLOT 0000000000000000 compute_checksum + 0'),
        ('code',   '  000000004010  000300000007 R_X86_64_JUMP_SLOT 0000000000000000 getpid@GLIBC_2.2.5 + 0'),
        ('code',   '  000000004018  000400000007 R_X86_64_JUMP_SLOT 0000000000000000 printf@GLIBC_2.2.5 + 0'),
        ('success','  000000004020  000500000007 R_X86_64_JUMP_SLOT 0000000000000000 verify_token + 0'),
        ('blank', ''),
        ('dim', '# [Elf64_Rela Struct Breakdown for verify_token]'),
        ('highlight','- r_offset : 0x00004020  (Target GOT slot to be rewritten by dynamic linker)'),
        ('highlight','- r_info   : 0x000500000007 (High 32b: Symbol Index 5 in .dynsym, Low 32b: R_X86_64_JUMP_SLOT)'),
        ('dim',      '- r_addend : 0x00000000  (Explicit addend value)')
    ]
    with open(f"{OUTPUT_DIR}/09-relocation-byte-analysis.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("Relocation Table: R_X86_64_JUMP_SLOT & Elf64_Rela Breakdown", lines_09_reloc, 840))

    print(f"[+] All 11 terminal SVGs successfully generated in {OUTPUT_DIR}")

if __name__ == '__main__':
    build_all_svgs()
