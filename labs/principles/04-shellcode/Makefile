ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    RUNNER  = 
endif

CFLAGS ?= -O0 -g -Wall -Wextra -z execstack

TARGET = shellcode_tester

.PHONY: all run run-exec clean

all: $(TARGET)

$(TARGET): shellcode_tester.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	@echo "=== Running Shellcode Inspection on $(ARCH) ==="
	$(RUNNER) ./$(TARGET)

run-exec: $(TARGET)
	@echo "=== Executing Shellcode on $(ARCH) ==="
	$(RUNNER) ./$(TARGET) --execute

clean:
	rm -f $(TARGET)
