ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    READELF = aarch64-linux-gnu-readelf
    OBJDUMP = aarch64-linux-gnu-objdump
    STRIP   = aarch64-linux-gnu-strip
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    READELF = readelf
    OBJDUMP = objdump
    STRIP   = strip
    RUNNER  = 
endif

CFLAGS ?= -Wall -Wextra

TARGET_DEFAULT = auth_demo
TARGET_OVERRIDE = auth_override

.PHONY: all run run-override demo-conflict demo-local inspect-symbols demo-strip clean

all: $(TARGET_DEFAULT) $(TARGET_OVERRIDE)

# 1. Normal link (Weak symbol in token_validator.c used)
$(TARGET_DEFAULT): auth_main.c token_validator.c
	$(CC) $(CFLAGS) -O2 $^ -o $@

# 2. Override link (Strong symbol in auth_hook.c replaces weak symbol)
$(TARGET_OVERRIDE): auth_main.c token_validator.c auth_hook.c
	$(CC) $(CFLAGS) -O2 $^ -o $@

run: $(TARGET_DEFAULT)
	@echo "=== [1] Running Default Build (Weak Logger) [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET_DEFAULT)

run-override: $(TARGET_OVERRIDE)
	@echo "=== [2] Running Hardened Override Build (Strong Logger) [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET_OVERRIDE)

# 3. Deliberately trigger Strong-Strong symbol collision
demo-conflict:
	@echo "=== [3] Deliberate Symbol Conflict (Multiple Definition) [$(ARCH)] ==="
	-$(CC) $(CFLAGS) auth_main.c token_validator.c token_conflict.c -o test_conflict 2>&1

# 4. Deliberately trigger undefined reference due to static LOCAL scoping
demo-local:
	@echo "=== [4] Deliberate Undefined Reference (Static Scoping) [$(ARCH)] ==="
	-$(CC) $(CFLAGS) auth_main.c token_local.c -o test_local 2>&1

inspect-symbols:
	@echo "=== [5] Inspecting Symbol Binding (GLOBAL vs LOCAL) [$(ARCH)] ==="
	$(CC) $(CFLAGS) -c token_validator.c -o token_validator.o
	$(CC) $(CFLAGS) -c token_local.c -o token_local.o
	@echo "--- token_validator.o (g_auth_counter = GLOBAL) ---"
	$(READELF) -s token_validator.o | grep g_auth_counter
	@echo "--- token_local.o (g_auth_counter = LOCAL) ---"
	$(READELF) -s token_local.o | grep g_auth_counter

demo-strip: $(TARGET_DEFAULT)
	@echo "=== [6] Symbol Stripping Demonstration (.symtab vs .dynsym) [$(ARCH)] ==="
	@echo "[+] Symbol count BEFORE strip:"
	$(READELF) -S $(TARGET_DEFAULT) | grep -E '\.symtab|\.dynsym'
	@echo "[+] Executing program before strip:"
	$(RUNNER) ./$(TARGET_DEFAULT) > /dev/null && echo "    -> Executed successfully!"
	@echo "[+] Stripping non-dynamic symbols (strip --strip-all)..."
	cp $(TARGET_DEFAULT) $(TARGET_DEFAULT)_stripped
	$(STRIP) --strip-all $(TARGET_DEFAULT)_stripped
	@echo "[+] Section headers AFTER strip (.symtab is gone, .dynsym remains):"
	$(READELF) -S $(TARGET_DEFAULT)_stripped | grep -E '\.symtab|\.dynsym' || true
	@echo "[+] Executing stripped binary:"
	$(RUNNER) ./$(TARGET_DEFAULT)_stripped > /dev/null && echo "    -> Executed successfully without .symtab!"

clean:
	rm -f $(TARGET_DEFAULT) $(TARGET_OVERRIDE) $(TARGET_DEFAULT)_stripped test_conflict test_local *.o
