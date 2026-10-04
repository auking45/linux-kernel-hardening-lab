# Linux Kernel Hardening Lab - Scenario 03 Makefile
CC = clang
CFLAGS ?= -O2 -Wall -Wextra

TARGET = smap_demo
SRCS = smap_demo.c

.PHONY: all clean run-normal run-attack run-hardened

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

run-normal: $(TARGET)
	./$(TARGET) --normal

run-attack: $(TARGET)
	./$(TARGET) --attack

run-hardened: $(TARGET)
	./$(TARGET) --hardened

clean:
	rm -f $(TARGET)
