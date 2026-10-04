CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra

TARGET_DEFAULT = sym_demo_default
TARGET_OVERRIDE = sym_demo_override

.PHONY: all run run-override inspect-symbols inspect-reloc clean

all: $(TARGET_DEFAULT) $(TARGET_OVERRIDE)

# Build without override (Weak symbol used)
$(TARGET_DEFAULT): main.c calc.c
	$(CC) $(CFLAGS) $^ -o $@

# Build with override (Strong symbol in weak_override.c replaces weak in calc.c)
$(TARGET_OVERRIDE): main.c calc.c weak_override.c
	$(CC) $(CFLAGS) $^ -o $@

run: $(TARGET_DEFAULT)
	@echo "=== [1] Running Default Build (Weak Symbol in effect) ==="
	./$(TARGET_DEFAULT)

run-override: $(TARGET_OVERRIDE)
	@echo "=== [2] Running Override Build (Strong Symbol overrides Weak) ==="
	./$(TARGET_OVERRIDE)

inspect-symbols: calc.c
	$(CC) $(CFLAGS) -c calc.c -o calc.o
	@echo "=== Symbol Table of calc.o (W indicates WEAK, T indicates TEXT/GLOBAL) ==="
	nm calc.o

inspect-reloc: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o
	@echo "=== Relocation Entries of main.o (readelf -r) ==="
	readelf -r main.o

clean:
	rm -f $(TARGET_DEFAULT) $(TARGET_OVERRIDE) *.o
