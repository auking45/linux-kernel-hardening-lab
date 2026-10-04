CC ?= clang
CFLAGS ?= -O0 -g -Wall -Wextra

TARGET = address_space_demo

.PHONY: all run run-maps clean

all: $(TARGET)

$(TARGET): address_space_demo.c
	$(CC) $(CFLAGS) $< -o $@

run: $(TARGET)
	./$(TARGET)

run-maps: $(TARGET)
	./$(TARGET) --maps

clean:
	rm -f $(TARGET)
