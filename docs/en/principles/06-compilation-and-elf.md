# 06. Compilation Process and ELF Architecture (Compilation & ELF File Format)

Investigating the low-level toolchain pipeline converting source text into machine code, and the **Dual View architecture (Linking View vs Execution View)** governing the Executable and Linkable Format (ELF).

---

## 1. Learning Objectives & Overview

- Understand how C code progresses through lexical analysis, syntax parsing, intermediate representation (IR), and assembly into an ELF binary.
- Examine why the ELF specification provides both a **Linking View (Section Header oriented)** for static linkers and an **Execution View (Program Header oriented)** for operating system loaders.
- Analyze the 64-byte `Elf64_Ehdr` structure and the kernel's validation of magic bytes (`\x7fELF`).
- Parse key program segments (`PT_LOAD`, `PT_INTERP`, `PT_GNU_STACK`) referenced by the Linux kernel when materializing virtual memory areas (VMAs).

---

## 2. Interactive ELF Architecture & Dual View Diagram

Explore the dual view mapping and W^X memory permissions through the interactive diagram below:

<div style="width: 100%; height: 600px; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/06-elf-structure.html" style="width: 100%; height: 100%; border: none;"></iframe>
</div>

---

## 3. Toolchain Code Transformation Pipeline

High-level C syntax is downgraded to CPU opcodes across several compiler phases:

```mermaid
flowchart LR
    A["C Source Code"] --> B["Lexical Analysis (Lexer)"]
    B --> C["Syntax Analysis (Parser: AST)"]
    C --> D["Intermediate Representation (LLVM IR)"]
    D --> E["Optimization Passes"]
    E --> F["Code Generation (ASM: .s)"]
    F --> G["Assembler (as ➔ .o)"]
    G --> H["Linker (ld ➔ ELF64)"]

    style A fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#fff
    style D fill:#1e293b,stroke:#a855f7,stroke-width:2px,color:#fff
    style H fill:#1e293b,stroke:#10b981,stroke-width:2px,color:#fff
```

1. **Lexical and Syntax Parsing**:
   - Tokenizes raw characters into syntax tokens, building an Abstract Syntax Tree (AST).
2. **Intermediate Representation & Optimization**:
   - Generates architecture-neutral IR (LLVM IR) for optimization passes (dead code elimination, loop unrolling).
3. **Code Generation & Assembly**:
   - Emits target assembly instructions, mapped 1:1 into relocatable object files (`.o`).

---

## 4. Dual View Architecture: Linking vs Execution

The ELF specification serves two separate consumers across the binary lifecycle:

```
[ Linking View: Section Focused ]               [ Execution View: Segment Focused ]
  (Used by ld and GDB)                            (Used by kernel load_elf_binary)
┌─────────────────────────┐                   ┌─────────────────────────┐
│       ELF Header        │                   │       ELF Header        │
├─────────────────────────┤                   ├─────────────────────────┤
│  Program Header Table   │ (Optional)        │  Program Header Table   │ (Required!)
├─────────────────────────┤                   ├─────────────────────────┤
│  .text / .init / .plt   │ ──(Bundling)────> │  PT_LOAD 1 (RX)         │ (Code Segment)
├─────────────────────────┤                   ├─────────────────────────┤
│  .rodata / .eh_frame    │ ──(Bundling)────> │  PT_LOAD 2 (R--)        │ (Read-Only Segment)
├─────────────────────────┤                   ├─────────────────────────┤
│  .data / .bss / .got    │ ──(Bundling)────> │  PT_LOAD 3 (RW-)        │ (Data Segment)
├─────────────────────────┤                   ├─────────────────────────┤
│  Section Header Table   │ (Required!)       │  Section Header Table   │ (Optional / Strippable)
└─────────────────────────┘                   └─────────────────────────┘
```

### 4.1 Key ELF Header Fields (`Elf64_Ehdr`)

| Field Name | Type | Purpose & Security Implications |
| :--- | :--- | :--- |
| `e_ident[EI_MAG0..3]` | `unsigned char[4]` | ELF Magic bytes (`\x7fELF`). Validated first by the kernel |
| `e_type` | `Elf64_Half` | `ET_EXEC` (Fixed address executable) or `ET_DYN` (PIE / Shared object) |
| `e_machine` | `Elf64_Half` | Target architecture (`EM_X86_64 = 62`, `EM_AARCH64 = 183`) |
| `e_entry` | `Elf64_Addr` | Virtual memory address of initial execution entry point (`_start`) |
| `e_phoff` / `e_phnum` | `Elf64_Off / Half` | Offset and count of Program Header Table entries |
| `e_shoff` / `e_shnum` | `Elf64_Off / Half` | Offset and count of Section Header Table entries |

---

## 5. Lab Source Code & Direct ELF Parsing

- **Lab Source Code**: [`elf_inspector.c`](../../assets/labs/principles/06-elf-structure/elf_inspector.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/06-elf-structure/elf_inspector.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/06-elf-structure/Makefile)

### 5.1 Building and Running the Parser

```bash
cd labs/principles/06-elf-structure
make inspect-self
```

```
============================================================
 64-bit ELF Header Inspection: elf_inspector
============================================================
[1] Magic Bytes      : 7f 45 4c 46 (ASCII: \x7fELF)
[2] Architecture     : ELF64 (64-bit)
[3] Data Encoding    : 2's complement, Little Endian
[4] Entry Point      : 0x401130
[5] Program Headers  : Offset 0x40 (13 entries, size 56 bytes)
[6] Section Headers  : Offset 0x3890 (30 entries, size 64 bytes)
============================================================

=== [Execution View] Program Headers (Segments) ===
Type               Offset     VirtAddr           MemSize    Flags 
-----------------------------------------------------------------
PT_PHDR            0x40       0x400040           0x2d8      R--
PT_INTERP          0x318      0x400318           0x1c       R--
PT_LOAD            0x0        0x400000           0x780      R--
PT_LOAD            0x1000     0x401000           0x691      R-E
PT_LOAD            0x2000     0x402000           0x6cc      R--
PT_LOAD            0x2de8     0x403de8           0x2a8      RW-
PT_GNU_STACK       0x0        0x0                0x0        RW-
PT_GNU_RELRO       0x2de8     0x403de8           0x218      R--
```

- Confirm separation of permissions across segments: `PT_LOAD R-E` for text, `PT_LOAD RW-` for data, and `PT_GNU_STACK RW-` indicating NX/DEP enforcement.

---

## 6. Summary & Next Chapter

- ELF binaries present dual perspectives: sections for linking and segments for execution.
- In the next chapter, we investigate how symbols are bound and addresses resolved: **[07. Symbols, Resolution, and Relocation Mechanics](07-symbols-and-linking.md)**.
