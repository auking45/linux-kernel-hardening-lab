CC ?= clang
CFLAGS ?= -O0 -g -Wall -Wextra

TARGET = hello

.PHONY: all run inspect clean

all: $(TARGET)

$(TARGET): hello.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	@echo "=== [1] Running Hello World Binary ==="
	./$(TARGET)

inspect: $(TARGET)
	@echo "=== [2] ELF Header Inspection (ELF Magic & Entry Point) ==="
	readelf -h $(TARGET) | head -n 14
	@echo ""
	@echo "=== [3] ELF Program Headers (Segments Loaded by Kernel) ==="
	readelf -l $(TARGET)
	@echo ""
	@echo "=== [4] ELF Section Headers (.text, .rodata, .data, .bss) ==="
	readelf -S $(TARGET) | grep -E '(\.text|\.rodata|\.data|\.bss)'
	@echo ""
	@echo "=== [5] Symbol Table Inspection (main & global symbols) ==="
	nm $(TARGET) | grep -E '(main|g_greeting|g_run_counter)'

clean:
	rm -f $(TARGET)
