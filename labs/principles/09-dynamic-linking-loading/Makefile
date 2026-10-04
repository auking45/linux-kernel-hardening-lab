CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra

LIB_SHARED = libplugin.so
TARGET_DLOPEN = dlopen_demo
TARGET_PLT = plt_got_inspector

.PHONY: all run-dlopen run-plt inspect-got clean

all: $(LIB_SHARED) $(TARGET_DLOPEN) $(TARGET_PLT)

$(LIB_SHARED): plugin.c
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

$(TARGET_DLOPEN): dlopen_demo.c
	$(CC) $(CFLAGS) $< -ldl -o $@

$(TARGET_PLT): plt_got_inspector.c
	$(CC) $(CFLAGS) $< -o $@

run-dlopen: $(LIB_SHARED) $(TARGET_DLOPEN)
	@echo "=== [1] Running Runtime Dynamic Loading (dlopen) ==="
	./$(TARGET_DLOPEN)

run-plt: $(TARGET_PLT)
	@echo "=== [2] Running PLT/GOT Resolution Inspector ==="
	./$(TARGET_PLT)

inspect-got: $(TARGET_PLT)
	@echo "=== Dynamic Section & GOT Entries of plt_got_inspector ==="
	readelf -r $(TARGET_PLT)
	@echo ""
	@echo "=== Disassembly of .plt section ==="
	objdump -d -j .plt $(TARGET_PLT)

clean:
	rm -f $(LIB_SHARED) $(TARGET_DLOPEN) $(TARGET_PLT)
