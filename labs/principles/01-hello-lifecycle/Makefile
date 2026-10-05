ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    READELF = aarch64-linux-gnu-readelf
    NM      = aarch64-linux-gnu-nm
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    READELF = readelf
    NM      = nm
    RUNNER  = 
endif

CFLAGS ?= -O0 -g -Wall -Wextra
TARGET = hello

.PHONY: all run inspect clean

all: $(TARGET)

$(TARGET): hello.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	@echo "=== [1] Running Hello World Binary [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET)

inspect: $(TARGET)
	@echo "=== [2] ELF Header Inspection (ELF Magic & Entry Point) [$(ARCH)] ==="
	$(READELF) -h $(TARGET) | head -n 14
	@echo ""
	@echo "=== [3] ELF Program Headers (Segments Loaded by Kernel) [$(ARCH)] ==="
	$(READELF) -l $(TARGET)
	@echo ""
	@echo "=== [4] ELF Section Headers (.text, .rodata, .data, .bss) [$(ARCH)] ==="
	$(READELF) -S $(TARGET) | grep -E '(\.text|\.rodata|\.data|\.bss)'
	@echo ""
	@echo "=== [5] Symbol Table Inspection (main & global symbols) [$(ARCH)] ==="
	$(NM) $(TARGET) | grep -E '(main|g_greeting|g_run_counter)'

clean:
	rm -f $(TARGET)
