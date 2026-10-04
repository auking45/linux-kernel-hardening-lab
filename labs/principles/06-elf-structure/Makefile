CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra

TARGET = elf_inspector

.PHONY: all run inspect-self inspect-system clean

all: $(TARGET)

$(TARGET): elf_inspector.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	./$(TARGET)

inspect-self: $(TARGET)
	./$(TARGET) $(TARGET)

inspect-system: $(TARGET)
	./$(TARGET) /bin/ls

clean:
	rm -f $(TARGET)
