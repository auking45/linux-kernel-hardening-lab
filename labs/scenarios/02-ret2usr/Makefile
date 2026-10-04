# ==============================================================================
# Makefile for Scenario 02: ret2usr & SMEP/PXN Hardware Defense Simulation
# ==============================================================================

CC = clang
CFLAGS ?= -O2 -Wall -Wextra

TARGET = ret2usr_demo

all: $(TARGET)

$(TARGET): ret2usr_demo.c
	$(CC) $(CFLAGS) $< -o $@

run-normal: $(TARGET)
	./$(TARGET) 1

run-attack: $(TARGET)
	./$(TARGET) 2

run-hardened: $(TARGET)
	./$(TARGET) 3

clean:
	rm -f $(TARGET)

.PHONY: all run-normal run-attack run-hardened clean
