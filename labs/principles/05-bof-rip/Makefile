CC ?= clang
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie -fno-omit-frame-pointer -Wall -Wextra

TARGET = bof_demo

.PHONY: all run run-normal run-attack clean

all: $(TARGET)

$(TARGET): bof_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: run-normal

run-normal: $(TARGET)
	./$(TARGET)

run-attack: $(TARGET)
	./$(TARGET) --attack

clean:
	rm -f $(TARGET)
