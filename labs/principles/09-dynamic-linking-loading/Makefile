CC = gcc-13
CFLAGS ?= -Wall -Wextra -g -O0

LIB_SHARED = libsecure.so
TARGET_DYN = secvault_dyn
LIB_PLUGIN = libplugin.so
TARGET_DLOPEN = dlopen_demo

.PHONY: all run run-dlopen inspect-interp inspect-dynamic inspect-got trace-lazy-binding clean

all: $(LIB_SHARED) $(TARGET_DYN) $(LIB_PLUGIN) $(TARGET_DLOPEN)

$(LIB_SHARED): libsecure.c
	$(CC) -fPIC -shared $< -o $@

# Compile with -z lazy explicitly so lazy binding is enabled on modern systems
$(TARGET_DYN): secvault_dyn.c $(LIB_SHARED)
	$(CC) $(CFLAGS) -Wl,-z,lazy secvault_dyn.c -L. -lsecure -Wl,-rpath,. -o $@

$(LIB_PLUGIN): plugin.c
	$(CC) -fPIC -shared $< -o $@

$(TARGET_DLOPEN): dlopen_demo.c
	$(CC) $(CFLAGS) $< -ldl -o $@

run: $(TARGET_DYN)
	@echo "=== [1] Running Dynamically Linked Program ==="
	./$(TARGET_DYN)

run-dlopen: $(LIB_PLUGIN) $(TARGET_DLOPEN)
	@echo "=== [2] Running dlopen/dlsym Runtime Dynamic Loading ==="
	./$(TARGET_DLOPEN)

inspect-interp: $(TARGET_DYN)
	@echo "=== [3] Interpreter Path (.interp) ==="
	readelf -p .interp $(TARGET_DYN)

inspect-dynamic: $(TARGET_DYN)
	@echo "=== [4] Dynamic Section: DT_NEEDED Dependencies (readelf -d) ==="
	readelf -d $(TARGET_DYN) | grep -E 'NEEDED|RPATH|RUNPATH'

inspect-got: $(TARGET_DYN)
	@echo "=== [5] Relocation Entries (.rela.plt / GOT entries) ==="
	readelf -r $(TARGET_DYN)
	@echo ""
	@echo "=== Disassembly of .plt section ==="
	objdump -d -j .plt $(TARGET_DYN)

trace-lazy-binding: $(TARGET_DYN)
	@echo "=== [6] GDB Batch Tracing of GOT Before & After 1st Call ==="
	gdb -q -nx -batch -x trace_got.gdb ./$(TARGET_DYN)

clean:
	rm -f $(LIB_SHARED) $(TARGET_DYN) $(LIB_PLUGIN) $(TARGET_DLOPEN) *.o
