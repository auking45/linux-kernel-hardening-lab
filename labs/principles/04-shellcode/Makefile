CC ?= clang
CFLAGS ?= -O0 -g -Wall -Wextra -z execstack

TARGET = shellcode_tester

.PHONY: all run run-exec clean

all: $(TARGET)

$(TARGET): shellcode_tester.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	./$(TARGET)

run-exec: $(TARGET)
	./$(TARGET) --execute

clean:
	rm -f $(TARGET)
