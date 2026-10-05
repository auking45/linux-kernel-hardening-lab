ARCH ?= aarch64

ifeq ($(ARCH), aarch64)
    CC      = aarch64-linux-gnu-gcc
    RUNNER  = qemu-aarch64 -L /usr/aarch64-linux-gnu
else
    CC      = gcc-13
    RUNNER  = 
endif

CFLAGS ?= -O0 -g -Wall -Wextra

TARGET = address_space_demo

.PHONY: all run run-maps clean

all: $(TARGET)

$(TARGET): address_space_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	@echo "=== Running $(TARGET) on $(ARCH) ==="
	$(RUNNER) ./$(TARGET)

run-maps: $(TARGET)
	@echo "=== Running $(TARGET) with Maps on $(ARCH) ==="
	$(RUNNER) ./$(TARGET) --maps

clean:
	rm -f $(TARGET)
