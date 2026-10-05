CC = gcc-13
CFLAGS ?= -Wall -Wextra -O2
AR ?= ar

LIB_STATIC = libsecure.a
TARGET_DYN = secvault_dyn
TARGET_STATIC = secvault_static

.PHONY: all run-dyn run-static inspect-archive inspect-interp inspect-entry compare clean

all: $(LIB_STATIC) $(TARGET_DYN) $(TARGET_STATIC)

$(LIB_STATIC): crypto_mac.c token_validator.c
	$(CC) $(CFLAGS) -c crypto_mac.c -o crypto_mac.o
	$(CC) $(CFLAGS) -c token_validator.c -o token_validator.o
	$(AR) rcs $@ crypto_mac.o token_validator.o

$(TARGET_DYN): secvault.c $(LIB_STATIC)
	$(CC) $(CFLAGS) secvault.c -L. -lsecure -o $@

$(TARGET_STATIC): secvault.c $(LIB_STATIC)
	$(CC) $(CFLAGS) -static secvault.c -L. -lsecure -o $@

run-dyn: $(TARGET_DYN)
	@echo "=== [1] Running Dynamically Linked secvault_dyn ==="
	./$(TARGET_DYN)

run-static: $(TARGET_STATIC)
	@echo "=== [2] Running Statically Linked secvault_static ==="
	./$(TARGET_STATIC)

inspect-archive: $(LIB_STATIC)
	@echo "=== [3] Archive Contents (ar -t) & Symbol Table (readelf -a) ==="
	$(AR) -t $(LIB_STATIC)
	readelf -s $(LIB_STATIC) | grep -E 'compute_mac|validate_security_token'

inspect-interp: $(TARGET_DYN) $(TARGET_STATIC)
	@echo "=== [4] Program Headers: PT_INTERP Check ==="
	@echo "--- secvault_dyn (Has PT_INTERP: /lib64/ld-linux-x86-64.so.2) ---"
	readelf -l $(TARGET_DYN) | grep -A 1 INTERP || true
	@echo "--- secvault_static (Self-contained: NO PT_INTERP) ---"
	readelf -l $(TARGET_STATIC) | grep -A 1 INTERP || echo "    [+] PT_INTERP is absent! Kernel directly jumps to e_entry."

inspect-entry: $(TARGET_STATIC)
	@echo "=== [5] Entry Point & _start Disassembly ==="
	readelf -h $(TARGET_STATIC) | grep "Entry point"
	objdump -d -j .text $(TARGET_STATIC) | head -n 25

compare: all
	@echo "=== [6] Binary Size & Dependency Comparison ==="
	ls -lh $(TARGET_DYN) $(TARGET_STATIC)
	@echo "--- ldd secvault_dyn ---"
	ldd $(TARGET_DYN)
	@echo "--- ldd secvault_static ---"
	-ldd $(TARGET_STATIC)

clean:
	rm -f $(LIB_STATIC) crypto_mac.o token_validator.o $(TARGET_DYN) $(TARGET_STATIC)
