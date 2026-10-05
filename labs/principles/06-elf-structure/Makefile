ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC = aarch64-linux-gnu-gcc
    READELF = aarch64-linux-gnu-readelf
    OBJDUMP = aarch64-linux-gnu-objdump
    RUNNER = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC = gcc-13
    READELF = readelf
    OBJDUMP = objdump
    RUNNER = 
endif

CFLAGS ?= -Wall -Wextra

TARGET_INSPECTOR = elf_inspector
TARGET_VAULT = vault_core

.PHONY: all run pipeline inspect-header inspect-sections inspect-strings inspect-symbols inspect-debug clean

all: $(TARGET_INSPECTOR) $(TARGET_VAULT)

$(TARGET_INSPECTOR): elf_inspector.c
	$(CC) $(CFLAGS) -O2 $< -o $@

$(TARGET_VAULT): vault_core.c
	$(CC) $(CFLAGS) -O2 -g $< -o $@

run: $(TARGET_VAULT)
	@echo "=== Running $(TARGET_VAULT) on $(ARCH) ==="
	$(RUNNER) ./$(TARGET_VAULT)

# Generate intermediate compilation pipeline artifacts (.i, .s, .o)
pipeline: vault_core.c
	@echo "=== [1] Generating Preprocessed (.i), Assembly (.s), and Object (.o) files ($(ARCH)) ==="
	$(CC) -v --save-temps -O2 -g vault_core.c -o $(TARGET_VAULT) 2> gcc_verbose.log
	@echo "[+] Generated: vault_core.i, vault_core.s, vault_core.o, $(TARGET_VAULT)"

inspect-header: $(TARGET_VAULT)
	@echo "=== [2] ELF Header Comparison (Relocatable .o vs Executable) [$(ARCH)] ==="
	@echo "--- vault_core.o ---"
	$(READELF) -h vault_core.o 2>/dev/null || true
	@echo "--- vault_core ---"
	$(READELF) -h $(TARGET_VAULT)

inspect-sections: $(TARGET_VAULT)
	@echo "=== [3] Section Header Table (.text, .rodata, .data, .bss) [$(ARCH)] ==="
	$(READELF) -S $(TARGET_VAULT)

inspect-strings: $(TARGET_VAULT)
	@echo "=== [4] String Dumps (.rodata, .comment, .strtab) [$(ARCH)] ==="
	@echo "--- .rodata ---"
	$(READELF) -p .rodata $(TARGET_VAULT)
	@echo "--- .comment ---"
	$(READELF) -p .comment $(TARGET_VAULT)

inspect-symbols: $(TARGET_VAULT)
	@echo "=== [5] Symbol Table & puts Optimization Check [$(ARCH)] ==="
	$(READELF) -s vault_core.o 2>/dev/null || true

inspect-debug: $(TARGET_VAULT)
	@echo "=== [6] DWARF Debug Sections Check (-g) [$(ARCH)] ==="
	$(READELF) -S $(TARGET_VAULT) | grep debug || true

clean:
	rm -f $(TARGET_INSPECTOR) $(TARGET_VAULT) vault_core_pipeline
	rm -f *.i *.s *.o gcc_verbose.log
