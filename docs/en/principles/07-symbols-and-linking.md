# 07. Symbols, Resolution, and Relocation Mechanics (Symbols & Relocation)

Analyzing how compilers and linkers bind variable and function names to memory addresses through **Symbol Resolution** and patch instruction operands via **Relocation**.

---

## 1. Learning Objectives & Overview

- Understand the layout of the ELF symbol table (`Elf64_Sym`) and the distinctions between Local, Global, and Weak symbols.
- Master the **Three Rules of Strong vs Weak Symbol Resolution** when multiple definitions collide.
- Compare symbol name mangling between C and C++.
- Compute relocation offsets using the standard formula: $\text{Offset} = S + A - P$.

---

## 2. Interactive Symbol Resolution & Relocation Diagram

Step through the 4 stages from unresolved symbols to patched opcodes below:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/07-symbols-linking.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. Symbol Table Architecture (`Elf64_Sym`)

Names declared in source code are represented within `.symtab`:

```c
typedef struct {
    Elf64_Word    st_name;  /* Offset into .strtab string table */
    unsigned char st_info;  /* Type (FUNC, OBJECT) and Binding (LOCAL, GLOBAL, WEAK) */
    unsigned char st_other; /* Visibility (DEFAULT, HIDDEN) */
    Elf64_Section st_shndx; /* Section index (SHN_UNDEF if unresolved) */
    Elf64_Addr    st_value; /* Section offset or final virtual address */
    Elf64_Xword   st_size;  /* Size of the symbol object */
} Elf64_Sym;
```

---

## 4. Three Rules of Strong vs. Weak Symbols

Functions and initialized global variables are **Strong symbols**, while uninitialized globals and `__attribute__((weak))` symbols are **Weak symbols**:

1. **Rule 1 (No Multiple Strong Symbols)**:
   - Multiple strong symbols with the same name trigger a fatal link error (`multiple definition of ...`).
2. **Rule 2 (Strong Overrides Weak)**:
   - Given one strong symbol and multiple weak symbols sharing a name, the linker **selects the strong definition** (Weak Symbol Overriding).
3. **Rule 3 (Arbitrary Weak Selection)**:
   - Given only weak definitions, the linker arbitrarily chooses one.

> [!TIP]
> **Library Function Interception**:
> Core C library functions (e.g., `malloc`, `free`) are provided as weak symbols, allowing performance profilers or security hooks to override standard routines cleanly.

---

## 5. Relocation Calculation Formula

Compilers emit placeholder bytes (`e8 00 00 00 00`) for unresolved calls, leaving relocation entries in `.rela.text`:

### 5.1 Common x86_64 Relocation Types

- **`R_X86_64_PC32` (32-bit PC-Relative Offset)**:
  $$\text{Offset} = S + A - P$$
  - $S$ (Symbol): Final virtual address of target function.
  - $A$ (Addend): Fixed adjustment constant (typically `-4`).
  - $P$ (Place): Address of the instruction being patched.
- **`R_X86_64_64` (64-bit Absolute Address)**:
  $$\text{Address} = S + A$$

---

## 6. Lab Source Code & Weak Symbol Override Lab

- **Lab Source Code**: [`main.c`](../../assets/labs/principles/07-symbols-linking/main.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/07-symbols-linking/main.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/07-symbols-linking/Makefile)

### 6.1 Default Build (Weak Symbol Active)

```bash
cd labs/principles/07-symbols-linking
make run
```

```
=== [1] Running Default Build (Weak Symbol in effect) ===
./sym_demo_default
============================================================
 Symbol Resolution & Relocation Demonstration
============================================================
[+] calculate_add(10, 20) = 30
[+] g_operation_count address: 0x404024 (val=1)
[+] Calling custom_hook() at 0x4011e0:
    [calc.c] Default WEAK hook executed (no override provided).
============================================================
```

### 6.2 Overridden Build (Strong Symbol Takes Precedence)

```bash
make run-override
```

```
=== [2] Running Override Build (Strong Symbol overrides Weak) ===
./sym_demo_override
============================================================
 Symbol Resolution & Relocation Demonstration
============================================================
[+] calculate_add(10, 20) = 30
[+] g_operation_count address: 0x404024 (val=1)
[+] Calling custom_hook() at 0x4011e0:
    [weak_override.c] ★ STRONG hook successfully overrode the weak symbol!
============================================================
```

---

## 7. Summary & Next Chapter

- Linkers resolve symbols through binding precedence and patch binary instruction targets via relocation formulas.
- In the next chapter, we combine modules into a standalone binary: **[08. Static Linking and Binary Loading](08-static-linking-and-loading.md)**.
