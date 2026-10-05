#!/usr/bin/env python3
"""
Generate Vector-Sharp Dark-Themed Terminal SVGs for Principles Labs (06-09)
Linux Kernel Hardening Lab - Dual-Architecture (AArch64 Default + x86_64 Comparison)
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
            svg_lines.append('    <tspan fill="#38bdf8" font-weight="bold">hardening-lab@arm64</tspan>')
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
        ('prompt', 'aarch64-linux-gnu-gcc -v --save-temps -O2 -g vault_core.c -o vault_core'),
        ('dim', '# [Pass 1] C Preprocessor (cpp) -> Header Inlining & Macro Expansion'),
        ('code', '[+] Generated: vault_core.i (Preprocessed C source: 55,630 lines)'),
        ('dim', '# [Pass 2] Compiler Engine (cc1 -O2) -> AArch64 Register Allocation (x0-x30)'),
        ('code', '[+] Generated: vault_core.s (GNU AArch64 Assembly text: 280 lines)'),
        ('dim', '# [Pass 3] Assembler (as) -> 32-bit Fixed Instruction Encoding (A64)'),
        ('code', '[+] Generated: vault_core.o (ELF 64-bit Relocatable Object, ARM aarch64)'),
        ('dim', '# [Pass 4] Linker (collect2 / ld) -> Symbol Resolution & Segment Packaging'),
        ('success', '[+] Generated: vault_core   (ELF 64-bit PIE Executable, ARM aarch64)'),
        ('blank', ''),
        ('prompt', 'file vault_core.* vault_core'),
        ('highlight', 'vault_core.i: C source, Unicode text, UTF-8 text'),
        ('highlight', 'vault_core.s: assembler source, ASCII text (AArch64 GAS)'),
        ('header',    'vault_core.o: ELF 64-bit LSB relocatable, ARM aarch64, version 1 (SYSV)'),
        ('success',   'vault_core:   ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked'),
        ('blank', ''),
        ('prompt', 'qemu-aarch64 -L /usr/aarch64-linux-gnu ./vault_core'),
        ('success', '=== Security Vault Service Online === (HSM Token Active on AArch64)')
    ]
    with open(f"{OUTPUT_DIR}/06-compiler-pipeline.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Compiler Pipeline: Intermediate Files (aarch64-linux-gnu-gcc)", lines_06_pipe, 840))

    # -------------------------------------------------------------
    # 2. 06-readelf-headers.svg
    # -------------------------------------------------------------
    lines_06_hdr = [
        ('prompt', 'aarch64-linux-gnu-readelf -h vault_core.o'),
        ('header', 'ELF Header (AArch64 Relocatable Object File):'),
        ('code',   '  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00'),
        ('code',   '  Class:                             ELF64'),
        ('code',   '  Data:                              2\'s complement, little endian'),
        ('warning','  Type:                              REL (Relocatable file)'),
        ('highlight','  Machine:                           AArch64 (EM_AARCH64 = 183)'),
        ('dim',    '  Entry point address:               0x0  <-- [No entry point defined yet!]'),
        ('dim',    '  Start of program headers:          0 (bytes into file) <-- [0 Segments]'),
        ('code',   '  Number of section headers:         29'),
        ('blank', ''),
        ('prompt', 'aarch64-linux-gnu-readelf -h vault_core'),
        ('header', 'ELF Header (AArch64 Position-Independent Executable):'),
        ('code',   '  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00'),
        ('success','  Type:                              DYN (Position-Independent Executable file)'),
        ('highlight','  Machine:                           AArch64 (EM_AARCH64 = 183)'),
        ('success','  Entry point address:               0x7c0  <-- [_start in .text]'),
        ('success','  Start of program headers:          64 (bytes into file)  <-- [9 Program Headers]'),
        ('code',   '  Number of section headers:         36')
    ]
    with open(f"{OUTPUT_DIR}/06-readelf-headers.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 ELF Header Comparison: Relocatable vs Executable (readelf -h)", lines_06_hdr, 840))

    # -------------------------------------------------------------
    # 3. 06-readelf-symbols-opt.svg
    # -------------------------------------------------------------
    lines_06_sym = [
        ('prompt', 'aarch64-linux-gnu-readelf -s vault_core.o'),
        ('header', 'Symbol table \'.symtab\' contains 32 entries (AArch64):'),
        ('dim',    '   Num:    Value          Size Type    Bind   Vis      Ndx Name'),
        ('highlight','   6: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    4 $d   <-- [ARM Mapping Symbol: Data]'),
        ('highlight','   8: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    5 $x   <-- [ARM Mapping Symbol: Code]'),
        ('code',   '    25: 0000000000000000   168 FUNC    GLOBAL DEFAULT    5 main'),
        ('warning','    26: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts  <-- [AArch64 Optimization!]'),
        ('dim',    '    27: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __printf_chk'),
        ('highlight','  29: 0000000000000000   256 OBJECT  GLOBAL DEFAULT    3 g_session_token (Section: .bss)'),
        ('code',   '    30: 0000000000000000     8 OBJECT  GLOBAL DEFAULT    7 g_banner'),
        ('success','    31: 0000000000000000     4 OBJECT  GLOBAL DEFAULT    2 g_vault_status  (Section: .data)'),
        ('blank', ''),
        ('dim', '# Note: ARM64 compiler uses Mapping Symbols ($x for A64 instructions, $d for literal pools).'),
        ('dim', '# printf() with constant string is automatically optimized to puts() symbol on AArch64.')
    ]
    with open(f"{OUTPUT_DIR}/06-readelf-symbols-opt.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Symbols & Mapping Symbols ($x, $d, puts optimization)", lines_06_sym, 840))

    # -------------------------------------------------------------
    # 4. 07-symbol-conflict-error.svg
    # -------------------------------------------------------------
    lines_07_conflict = [
        ('prompt', 'aarch64-linux-gnu-gcc auth_main.c token_validator.c token_conflict.c -o test_conflict'),
        ('error',  '/usr/bin/aarch64-linux-gnu-ld: /tmp/ccllcluP.o: in function \'verify_auth_token\':'),
        ('error',  'token_conflict.c:(.text+0x0): multiple definition of \'verify_auth_token\';'),
        ('error',  '/tmp/ccDCKPc8.o:token_validator.c:(.text+0x0): first defined here'),
        ('error',  'collect2: error: ld returned 1 exit status'),
        ('blank', ''),
        ('dim', '# [Root Cause Analysis on AArch64]'),
        ('warning','- Symbol: verify_auth_token (Type: FUNC, Bind: GLOBAL, Status: STRONG in both files)'),
        ('code',   '- Rule 1 of Linker Symbol Resolution: Multiple strong symbols cannot coexist!'),
        ('dim', '- Applies identically across AArch64 and x86_64 architectures.')
    ]
    with open(f"{OUTPUT_DIR}/07-symbol-conflict-error.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Linker Error: Multiple Definition Conflict (Rule 1)", lines_07_conflict, 840))

    # -------------------------------------------------------------
    # 5. 07-symbol-local-error.svg
    # -------------------------------------------------------------
    lines_07_local = [
        ('prompt', 'aarch64-linux-gnu-gcc auth_main.c token_local.c -o test_local'),
        ('error',  '/usr/bin/aarch64-linux-gnu-ld: in function \'main\':'),
        ('error',  'auth_main.c:(.text+0x74): undefined reference to \'g_auth_counter\''),
        ('error',  'collect2: error: ld returned 1 exit status'),
        ('blank', ''),
        ('prompt', 'aarch64-linux-gnu-readelf -s token_local.o | grep g_auth_counter'),
        ('warning','     5: 0000000000000000     4 OBJECT  LOCAL  DEFAULT    4 g_auth_counter'),
        ('blank', ''),
        ('dim', '# [Root Cause Analysis]'),
        ('dim', '- In token_local.c: declared as "static int g_auth_counter;"'),
        ('highlight','- LOCAL binding restricts visibility strictly to token_local.c translation unit.'),
        ('code',   '- auth_main.c references extern symbol, but AArch64 linker cannot find it in global pool.')
    ]
    with open(f"{OUTPUT_DIR}/07-symbol-local-error.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Linker Error: Undefined Reference due to LOCAL Binding", lines_07_local, 840))

    # -------------------------------------------------------------
    # 6. 07-symbol-strip-verification.svg
    # -------------------------------------------------------------
    lines_07_strip = [
        ('prompt', 'aarch64-linux-gnu-readelf -S auth_demo | grep -E \'\\.symtab|\\.dynsym\''),
        ('success','  [ 5] .dynsym           DYNSYM           00000000000002b8  000002b8  (Dynamic Symbols)'),
        ('header', '  [25] .symtab           SYMTAB           0000000000000000  00010040  (Static Debug Symbols)'),
        ('blank', ''),
        ('prompt', 'aarch64-linux-gnu-strip --strip-all auth_demo -o auth_demo_stripped'),
        ('prompt', 'aarch64-linux-gnu-readelf -S auth_demo_stripped | grep -E \'\\.symtab|\\.dynsym\''),
        ('success','  [ 5] .dynsym           DYNSYM           00000000000002b8  000002b8  (Preserved!)'),
        ('dim',    '  # Note: .symtab is completely eliminated; .dynsym retains SHF_ALLOC flag.'),
        ('blank', ''),
        ('prompt', 'qemu-aarch64 -L /usr/aarch64-linux-gnu ./auth_demo_stripped'),
        ('success','[+] Token verification result : VALID (AArch64 emulation)'),
        ('success','[+] Calling auth_event_logger : [DEFAULT-WEAK-LOGGER] Cycle completed'),
        ('dim',    '--> AArch64 binary executes flawlessly without .symtab!')
    ]
    with open(f"{OUTPUT_DIR}/07-symbol-strip-verification.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Symbol Stripping: .symtab Removal & QEMU Execution", lines_07_strip, 840))

    # -------------------------------------------------------------
    # 7. 08-static-archive-readelf.svg
    # -------------------------------------------------------------
    lines_08_ar = [
        ('prompt', 'aarch64-linux-gnu-ar rcs libsecure.a crypto_mac.o token_validator.o'),
        ('prompt', 'aarch64-linux-gnu-ar -t libsecure.a'),
        ('code',   'crypto_mac.o'),
        ('code',   'token_validator.o'),
        ('blank', ''),
        ('prompt', 'aarch64-linux-gnu-readelf -s libsecure.a'),
        ('header', 'File: libsecure.a(crypto_mac.o) [AArch64]'),
        ('success','    10: 0000000000000000    48 FUNC    GLOBAL DEFAULT    1 compute_mac'),
        ('header', 'File: libsecure.a(token_validator.o) [AArch64]'),
        ('success','    10: 0000000000000000    64 FUNC    GLOBAL DEFAULT    1 validate_security_token'),
        ('blank', ''),
        ('dim', '# AArch64 static archive packages relocatable .o objects with an internal symdef index.'),
        ('dim', '# Linker selectively extracts only the modules resolving unsatisfied symbols.')
    ]
    with open(f"{OUTPUT_DIR}/08-static-archive-readelf.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Static Archive: Member Inspection & Symbol Extraction", lines_08_ar, 840))

    # -------------------------------------------------------------
    # 8. 08-static-maps-comparison.svg
    # -------------------------------------------------------------
    lines_08_maps = [
        ('prompt', 'aarch64-linux-gnu-readelf -l secvault_static | grep -A 1 LOAD'),
        ('header', '  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000'),
        ('code',   '                 0x0000000000085188 0x0000000000085188  R E    0x10000 (Code: RX)'),
        ('header', '  LOAD           0x0000000000090000 0x00000000004a0000 0x00000000004a0000'),
        ('code',   '                 0x00000000000089e8 0x000000000000f680  RW     0x10000 (Data: RW)'),
        ('blank', ''),
        ('prompt', 'aarch64-linux-gnu-readelf -l secvault_static | grep INTERP'),
        ('warning','[+] PT_INTERP is absent! Kernel / Loader directly branches to e_entry (0x400700).'),
        ('blank', ''),
        ('prompt', 'qemu-aarch64 -L /usr/aarch64-linux-gnu ./secvault_static'),
        ('success','============================================================'),
        ('success',' Security Vault Service (PID: 80274 on AArch64)'),
        ('success','[+] Token validation: PASSED | Computed MAC: 0x651E2B18'),
        ('success','============================================================')
    ]
    with open(f"{OUTPUT_DIR}/08-static-maps-comparison.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Static Binary: PT_LOAD Segments & Kernel Direct Loading", lines_08_maps, 840))

    # -------------------------------------------------------------
    # 9. 09-gdb-lazy-binding-step1.svg
    # -------------------------------------------------------------
    lines_09_gdb1 = [
        ('prompt', 'aarch64-linux-gnu-objdump -d -j .plt secvault_dyn'),
        ('header', 'Disassembly of section .plt (AArch64 Procedure Linkage Table):'),
        ('blank', ''),
        ('dim', '# [1] PLT Header (.plt0 Trampoline)'),
        ('code',   ' 00000000000006e0 <.plt>:'),
        ('highlight','  6e0: stp   x16, x30, [sp, #-16]!  <-- [Push GOT slot (x16) & LR (x30)]'),
        ('code',   '  6e4: adrp  x16, 1f000             <-- [Compute GOT page via PC-relative]'),
        ('code',   '  6e8: ldr   x17, [x16, #4088]      <-- [Load dynamic resolver address]'),
        ('code',   '  6ec: add   x16, x16, #0xff8       <-- [Calculate GOT slot address]'),
        ('highlight','  6f0: br    x17                    <-- [Branch to _dl_runtime_resolve]'),
        ('blank', ''),
        ('dim', '# [2] Individual Function PLT Stub (verify_token@plt)'),
        ('code',   ' 0000000000000780 <verify_token@plt>:'),
        ('warning','  780: adrp  x16, 20000             <-- [PC-relative base of GOT entry]'),
        ('warning','  784: ldr   x17, [x16, #64]        <-- [Load target address from GOT]'),
        ('code',   '  788: add   x16, x16, #0x40        <-- [Slot pointer in x16]'),
        ('success','  78c: br    x17                    <-- [Indirect branch to function]')
    ]
    with open(f"{OUTPUT_DIR}/09-gdb-lazy-binding-step1.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 PLT Stub Disassembly & PC-Relative Dispatch (adrp + ldr + br)", lines_09_gdb1, 840))

    # -------------------------------------------------------------
    # 10. 09-gdb-lazy-binding-step2.svg
    # -------------------------------------------------------------
    lines_09_gdb2 = [
        ('prompt', 'qemu-aarch64 -L /usr/aarch64-linux-gnu -E LD_LIBRARY_PATH=. ./secvault_dyn'),
        ('header', '============================================================'),
        ('header', ' PLT / GOT Lazy Binding Demonstration (AArch64 Emulation)'),
        ('header', '============================================================'),
        ('warning','[*] [Call 1] Invoking verify_token() for the first time...'),
        ('dim',    '    -> Triggers AArch64 adrp/ldr into GOT -> branches to .plt0 trampoline'),
        ('dim',    '    -> _dl_runtime_resolve updates GOT slot with libsecure.so address'),
        ('success','[+] [Call 1 Result] AUTHORIZED'),
        ('blank', ''),
        ('success','[*] [Call 2] Invoking verify_token() for the second time...'),
        ('dim',    '    -> adrp/ldr directly branches to cached address via "br x17"! (0 linker overhead)'),
        ('success','[+] [Call 2 Result] AUTHORIZED'),
        ('blank', ''),
        ('dim', '# [Security Note] Full RELRO (-Wl,-z,relro,-z,now) resolves symbols on startup'),
        ('dim', '# and marks the .got segment read-only (mprotect r--p) to block GOT Overwrite.')
    ]
    with open(f"{OUTPUT_DIR}/09-gdb-lazy-binding-step2.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Dynamic Execution: Lazy Binding & Direct Branching (QEMU)", lines_09_gdb2, 840))

    # -------------------------------------------------------------
    # 11. 09-relocation-byte-analysis.svg
    # -------------------------------------------------------------
    lines_09_reloc = [
        ('prompt', 'aarch64-linux-gnu-readelf -r secvault_dyn'),
        ('header', 'Relocation section \'.rela.plt\' at offset 0x5e8 contains 9 entries (AArch64):'),
        ('dim',    '  Offset          Info           Type           Sym. Value    Sym. Name + Addend'),
        ('code',   '000000020000  000300000402 R_AARCH64_JUMP_SL 0000000000000000 __libc_start_main + 0'),
        ('code',   '000000020008  000500000402 R_AARCH64_JUMP_SL 0000000000000000 compute_checksum + 0'),
        ('code',   '000000020038  000c00000402 R_AARCH64_JUMP_SL 0000000000000000 printf@GLIBC_2.17 + 0'),
        ('success','000000020040  000d00000402 R_AARCH64_JUMP_SL 0000000000000000 verify_token + 0'),
        ('blank', ''),
        ('dim', '# [Elf64_Rela Struct Breakdown for verify_token on AArch64]'),
        ('highlight','- r_offset : 0x000000020040 (Target GOT entry address to be patched by dynamic linker)'),
        ('highlight','- r_info   : 0x000d00000402'),
        ('code',     '  * High 32b : 0x0000000d (Symbol Index 13 in .dynsym: "verify_token")'),
        ('code',     '  * Low 32b  : 0x00000402 (Type 1026: R_AARCH64_JUMP_SLOT)'),
        ('dim',      '- r_addend : 0x0000000000000000 (Explicit addend constant)')
    ]
    with open(f"{OUTPUT_DIR}/09-relocation-byte-analysis.svg", "w", encoding="utf-8") as f:
        f.write(create_terminal_svg("AArch64 Relocation Table: R_AARCH64_JUMP_SLOT & Elf64_Rela Breakdown", lines_09_reloc, 840))

    print(f"[+] All 11 AArch64 terminal SVGs successfully regenerated in {OUTPUT_DIR}")

if __name__ == '__main__':
    build_all_svgs()
