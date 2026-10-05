ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    RUNNER  = 
endif

CFLAGS ?= -O0 -g -fno-stack-protector -no-pie -fno-omit-frame-pointer -Wall -Wextra

TARGET = bof_demo

.PHONY: all run run-normal run-attack run-heap run-nop-sled clean

all: $(TARGET)

$(TARGET): bof_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: run-normal

run-normal: $(TARGET)
	@echo "=== [1] Running Normal Mode [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET)

run-attack: $(TARGET)
	@echo "=== [2] Running Stack FP Hijack Attack [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET) --stack-fp

run-heap: $(TARGET)
	@echo "=== [3] Running Heap Buffer Overflow Attack [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET) --heap-bof

run-nop-sled: $(TARGET)
	@echo "=== [4] Running NOP Sled Simulation [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET) --nop-sled

clean:
	rm -f $(TARGET)
