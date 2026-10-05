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

.PHONY: all run run-normal run-attack clean

all: $(TARGET)

$(TARGET): bof_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: run-normal

run-normal: $(TARGET)
	@echo "=== [1] Running Normal Mode [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET)

run-attack: $(TARGET)
	@echo "=== [2] Running Control Flow Hijack Attack [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET) --attack

clean:
	rm -f $(TARGET)
