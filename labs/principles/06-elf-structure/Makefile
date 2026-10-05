CC = gcc-13
CFLAGS ?= -Wall -Wextra

TARGET_INSPECTOR = elf_inspector
TARGET_VAULT = vault_core

.PHONY: all pipeline inspect-header inspect-sections inspect-strings inspect-symbols inspect-debug clean

all: $(TARGET_INSPECTOR) $(TARGET_VAULT)

$(TARGET_INSPECTOR): elf_inspector.c
	$(CC) $(CFLAGS) -O2 $< -o $@

$(TARGET_VAULT): vault_core.c
	$(CC) $(CFLAGS) -O2 -g $< -o $@

# Generate intermediate compilation pipeline artifacts (.i, .s, .o)
pipeline: vault_core.c
	@echo "=== [1] Generating Preprocessed (.i), Assembly (.s), and Object (.o) files ==="
	$(CC) -v --save-temps -O2 -g vault_core.c -o $(TARGET_VAULT) 2> gcc_verbose.log
	@echo "[+] Generated: vault_core.i, vault_core.s, vault_core.o, $(TARGET_VAULT)"

inspect-header: $(TARGET_VAULT)
	@echo "=== [2] ELF Header Comparison (Relocatable .o vs Executable) ==="
	@echo "--- vault_core.o ---"
	readelf -h vault_core.o 2>/dev/null || true
	@echo "--- vault_core ---"
	readelf -h $(TARGET_VAULT)

inspect-sections: $(TARGET_VAULT)
	@echo "=== [3] Section Header Table (.text, .rodata, .data, .bss) ==="
	readelf -S $(TARGET_VAULT)

inspect-strings: $(TARGET_VAULT)
	@echo "=== [4] String Dumps (.rodata, .comment, .strtab) ==="
	@echo "--- .rodata ---"
	readelf -p .rodata $(TARGET_VAULT)
	@echo "--- .comment ---"
	readelf -p .comment $(TARGET_VAULT)

inspect-symbols: $(TARGET_VAULT)
	@echo "=== [5] Symbol Table & puts Optimization Check ==="
	readelf -s vault_core.o 2>/dev/null || true

inspect-debug: $(TARGET_VAULT)
	@echo "=== [6] DWARF Debug Sections Check (-g) ==="
	readelf -S $(TARGET_VAULT) | grep debug || true

clean:
	rm -f $(TARGET_INSPECTOR) $(TARGET_VAULT) vault_core_pipeline
	rm -f *.i *.s *.o gcc_verbose.log
