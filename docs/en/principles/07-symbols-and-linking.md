# 07. Symbol Tables & Relocation Mechanisms (Symbols & Relocation)

In-depth analysis of how independent object modules (`.o`) are combined into a coherent executable binary through **Symbol Resolution** (binding variable and function names to memory addresses) and **Relocation** (patching instruction operand offsets).

---

## 1. Learning Objectives & Overview

- Deconstruct the byte fields of the ELF symbol table structure (`Elf64_Sym`) and understand symbol binding attributes (`GLOBAL`, `LOCAL`, `WEAK`).
- Analyze how the `static` keyword enforces `LOCAL` binding, isolating translation units and triggering linker `undefined reference` errors.
- Investigate the linker's **Three Golden Rules for Strong vs. Weak Symbol Resolution** and reproduce fatal duplicate definition conflicts (`multiple definition`).
- Demonstrate the runtime distinction between static symbols (`.symtab`) and dynamic symbols (`.dynsym`) through binary **Symbol Stripping (`strip`)**.
- Calculate low-level instruction operand patches using PC-relative relocation arithmetic (`S + A - P`).

---

## 2. Interactive Symbol Resolution & Relocation Diagram

Interact with the 4-phase timeline below to observe unresolved symbol collection, strong/weak conflict arbitration, section merging, and machine code byte relocation:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/07-symbols-linking.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. ELF Symbol Table Structure (`Elf64_Sym`) & Binding Scope

Every global function and variable is cataloged by the compiler into symbol tables used by the linker to resolve cross-module references:

```c
typedef struct {
    Elf64_Word    st_name;  /* Offset into .strtab string table (4B) */
    unsigned char st_info;  /* High 4b: Bind, Low 4b: Type (1B) */
    unsigned char st_other; /* Visibility: DEFAULT, HIDDEN, etc. (1B) */
    Elf64_Section st_shndx; /* Section index (SHN_UNDEF if unresolved) (2B) */
    Elf64_Addr    st_value; /* Section offset or resolved virtual address (8B) */
    Elf64_Xword   st_size;  /* Object byte size (8B) */
} Elf64_Sym; /* Total 24 bytes */
```

### 3.1 `LOCAL` vs. `GLOBAL` Binding: The `static` Scope Isolation

Declaring a variable or helper function as `static` instructs the compiler to emit the symbol with `STB_LOCAL` binding:

![Undefined Reference Error due to LOCAL Binding Terminal](../../assets/images/principles/07-symbol-local-error.svg)

```bash
gcc-13 -Wall -Wextra auth_main.c token_local.c -o test_local
```

```
/usr/bin/ld: in function 'main':
auth_main.c:(.text+0x82): undefined reference to 'g_auth_counter'
collect2: error: ld returned 1 exit status
```

```bash
readelf -s token_local.o | grep g_auth_counter
     4: 0000000000000000     4 OBJECT  LOCAL  DEFAULT    4 g_auth_counter
```

- In `token_local.c`, `static int g_auth_counter` is constrained to `LOCAL` binding, making it invisible outside its translation unit.
- Even though `auth_main.c` declares `extern int g_auth_counter;`, the static linker cannot locate it in the global symbol pool, aborting with a fatal `undefined reference` error.

---

## 4. Strong vs. Weak Symbol Resolution & Conflict Arbitration

The static linker (`ld`) enforces precise arbitration rules when multiple object files define symbols with identical names:

| Symbol Category | C Language Construct | Linker Precedence |
| :--- | :--- | :--- |
| **Strong Symbol** | Function definitions, initialized global variables (`int g_val = 10;`) | Highest (Duplicates prohibited) |
| **Weak Symbol** | Uninitialized global variables, functions with `__attribute__((weak))` | Replaceable (Lower precedence) |

### 4.1 Rule 1: Duplicate Strong Symbols Prohibited (`multiple definition`)

When two or more object files declare strong symbols sharing the same identifier, the linker immediately terminates:

![Linker Error: Multiple Definition Conflict Terminal](../../assets/images/principles/07-symbol-conflict-error.svg)

```bash
gcc-13 -Wall -Wextra auth_main.c token_validator.c token_conflict.c -o test_conflict
```

```
/usr/bin/ld: token_conflict.c:(.text+0x0): multiple definition of 'verify_auth_token'; 
token_validator.c:(.text+0x0): first defined here
collect2: error: ld returned 1 exit status
```

### 4.2 Rule 2: Strong Symbol Overrides Weak Symbol

When a strong symbol contends with one or more weak symbols, the linker silently adopts the **strong symbol**:
- `token_validator.c` defines a default audit logger marked with `__attribute__((weak))`.
- When `auth_hook.c` supplies a strong definition of `auth_event_logger`, the linker overrides the default routine without warning or error.

---

## 5. Symbol Stripping Verification: `.symtab` vs. `.dynsym`

ELF binaries maintain two distinct symbol tables serving different architectural purposes:

![Symbol Stripping Verification Terminal](../../assets/images/principles/07-symbol-strip-verification.svg)

```bash
# Before strip: Both symbol tables are present
readelf -S auth_demo | grep -E '\.symtab|\.dynsym'
  [ 6] .dynsym           DYNSYM           00000000000003d8  000003d8
  [28] .symtab           SYMTAB           0000000000000000  00003040

# Strip non-dynamic symbols
strip --strip-all auth_demo -o auth_demo_stripped

# After strip: .symtab eliminated, .dynsym retained
readelf -S auth_demo_stripped | grep -E '\.symtab|\.dynsym'
  [ 6] .dynsym           DYNSYM           00000000000003d8  000003d8
```

- **`.symtab` (Static Symbol Table)**: Houses local functions, `static` variables, and debugger symbols. It is not loaded into memory (`SHF_ALLOC` clear) and can be completely eliminated by `strip`.
- **`.dynsym` (Dynamic Symbol Table)**: Required at runtime by the dynamic linker (`ld-linux.so`) to resolve imports and exports. It is marked `SHF_ALLOC` and preserved even after `strip --strip-all`.
- The stripped executable `auth_demo_stripped` runs seamlessly, proving that application execution depends solely on `.dynsym`.

---

## 6. Relocation Arithmetic Mechanics (`S + A - P`)

Because the compiler cannot predict external symbol addresses during single-file translation, it leaves placeholder bytes (`e8 00 00 00 00`) and records relocation entries in `.rela.text`:

$$\text{Relocation Offset} = S + A - P$$

- **$S$ (Symbol)**: Final virtual address of the target function or variable determined by the linker.
- **$A$ (Addend)**: Explicit constant offset recorded in the relocation entry (typically `-4` for x86_64 call instructions).
- **$P$ (Place)**: Virtual memory address of the instruction operand being patched.

---

## 7. Practical Lab Source Code & Verification

- **Lab Source Code**: [`auth_main.c`](../../assets/labs/principles/07-symbols-linking/auth_main.c) | [`token_validator.c`](../../assets/labs/principles/07-symbols-linking/token_validator.c) | [`token_conflict.c`](../../assets/labs/principles/07-symbols-linking/token_conflict.c) | [`token_local.c`](../../assets/labs/principles/07-symbols-linking/token_local.c) | [`auth_hook.c`](../../assets/labs/principles/07-symbols-linking/auth_hook.c)
- **Lab Makefile**: [`Makefile`](../../assets/labs/principles/07-symbols-linking/Makefile)

```bash
cd labs/principles/07-symbols-linking

# 1. Execute default build with weak logger
make run

# 2. Execute hardened build with strong hook override
make run-override

# 3. Trigger multiple definition error (Rule 1 violation)
make demo-conflict

# 4. Trigger undefined reference error (LOCAL static scoping)
make demo-local

# 5. Inspect symbol bindings (GLOBAL vs. LOCAL) with readelf
make inspect-symbols

# 6. Verify symbol stripping behavior (.symtab vs. .dynsym)
make demo-strip
```

---

## 8. Summary & Next Module

- Symbol tables connect identifiers to physical memory addresses, while `static` scoping prevents symbol pollution across compilation units.
- Linkers resolve symbols deterministically using Strong/Weak precedence rules, and stripped binaries continue executing reliably via `.dynsym`.
- Next, examine how all dependencies and C runtime components are statically bundled into self-contained binaries in **[08. Static Linking and Loading](08-static-linking-and-loading.md)**.
