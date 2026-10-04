CC ?= clang
CFLAGS ?= -O0 -g -fno-omit-frame-pointer -fno-stack-protector -Wall -Wextra

TARGET = stack_frame_demo

.PHONY: all run disasm clean

all: $(TARGET)

$(TARGET): stack_frame_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	./$(TARGET)

disasm: $(TARGET)
	@echo "=== target_function Assembly (Prologue & Epilogue) ==="
	objdump -d --no-show-raw-insn $(TARGET) | sed -n '/<target_function>:/,/^$$/p'

clean:
	rm -f $(TARGET)
