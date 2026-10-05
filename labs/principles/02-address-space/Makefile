ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    RUNNER  = 
endif

CFLAGS ?= -O0 -g -Wall -Wextra

TARGET = address_space_demo

.PHONY: all run run-maps run-cow run-segv-null run-segv-rodata clean

all: $(TARGET)

$(TARGET): address_space_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	@echo "=== Running $(TARGET) on $(ARCH) ==="
	$(RUNNER) ./$(TARGET)

run-maps: $(TARGET)
	@echo "=== Running $(TARGET) with Maps on $(ARCH) ==="
	$(RUNNER) ./$(TARGET) --maps

run-cow: $(TARGET)
	@echo "=== Running $(TARGET) COW Demo on $(ARCH) ==="
	$(RUNNER) ./$(TARGET) --cow

run-segv-null: $(TARGET)
	@echo "=== Running $(TARGET) SEGV_MAPERR Demo on $(ARCH) ==="
	-$(RUNNER) ./$(TARGET) --segv-null

run-segv-rodata: $(TARGET)
	@echo "=== Running $(TARGET) SEGV_ACCERR Demo on $(ARCH) ==="
	-$(RUNNER) ./$(TARGET) --segv-rodata

clean:
	rm -f $(TARGET)
