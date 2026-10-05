ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    READELF = aarch64-linux-gnu-readelf
    OBJDUMP = aarch64-linux-gnu-objdump
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu -E LD_LIBRARY_PATH=.
    CFLAGS  ?= -Wall -Wextra -g -O0
else
    CC      = gcc-13
    READELF = readelf
    OBJDUMP = objdump
    RUNNER  = 
    CFLAGS  ?= -Wall -Wextra -g -O0
endif

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
	@echo "=== [1] Running Dynamically Linked Program [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET_DYN)

run-dlopen: $(LIB_PLUGIN) $(TARGET_DLOPEN)
	@echo "=== [2] Running dlopen/dlsym Runtime Dynamic Loading [$(ARCH)] ==="
	$(RUNNER) ./$(TARGET_DLOPEN)

inspect-interp: $(TARGET_DYN)
	@echo "=== [3] Interpreter Path (.interp) [$(ARCH)] ==="
	$(READELF) -p .interp $(TARGET_DYN)

inspect-dynamic: $(TARGET_DYN)
	@echo "=== [4] Dynamic Section: DT_NEEDED Dependencies (readelf -d) [$(ARCH)] ==="
	$(READELF) -d $(TARGET_DYN) | grep -E 'NEEDED|RPATH|RUNPATH'

inspect-got: $(TARGET_DYN)
	@echo "=== [5] Relocation Entries (.rela.plt / GOT entries) [$(ARCH)] ==="
	$(READELF) -r $(TARGET_DYN)
	@echo ""
	@echo "=== Disassembly of .plt section [$(ARCH)] ==="
	$(OBJDUMP) -d -j .plt $(TARGET_DYN)

trace-lazy-binding: $(TARGET_DYN)
ifeq ($(ARCH), aarch64)
	@echo "=== [6] AArch64 PLT Dispatch & Relocation Inspection ==="
	@echo "--- .plt disassembly (adrp + ldr + br x17) ---"
	$(OBJDUMP) -d -j .plt $(TARGET_DYN)
	@echo ""
	@echo "--- .rela.plt Dynamic Relocations (R_AARCH64_JUMP_SLOT) ---"
	$(READELF) -r $(TARGET_DYN)
	@echo ""
	@echo "[Tip] To trace GDB step-by-step on x86_64: make trace-lazy-binding ARCH=x86_64"
else
	@echo "=== [6] GDB Batch Tracing of GOT Before & After 1st Call [x86_64] ==="
	gdb -q -nx -batch -x trace_got.gdb ./$(TARGET_DYN)
endif

clean:
	rm -f $(LIB_SHARED) $(TARGET_DYN) $(LIB_PLUGIN) $(TARGET_DLOPEN) *.o
