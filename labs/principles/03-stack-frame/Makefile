ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    OBJDUMP = aarch64-linux-gnu-objdump
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    OBJDUMP = objdump
    RUNNER  = 
endif

CFLAGS ?= -O0 -g -fno-omit-frame-pointer -fno-stack-protector -Wall -Wextra

TARGET = stack_frame_demo

.PHONY: all run disasm clean

all: $(TARGET)

$(TARGET): stack_frame_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	@echo "=== Running $(TARGET) on $(ARCH) ==="
	$(RUNNER) ./$(TARGET)

disasm: $(TARGET)
	@echo "=== target_function Assembly (Prologue & Epilogue) [$(ARCH)] ==="
	$(OBJDUMP) -d --no-show-raw-insn $(TARGET) | sed -n '/<target_function>:/,/^$$/p'

clean:
	rm -f $(TARGET)
