CC = clang
CFLAGS ?= -O2 -Wall -Wextra

TARGET = humanoid_bof_demo

all: $(TARGET)

$(TARGET): humanoid_bof_demo.c
	$(CC) $(CFLAGS) $< -o $@

run-normal: $(TARGET)
	./$(TARGET) 1

run-attack: $(TARGET)
	./$(TARGET) 2

run-canary: $(TARGET)
	./$(TARGET) 3

clean:
	rm -f $(TARGET)

.PHONY: all clean run-normal run-attack run-canary
