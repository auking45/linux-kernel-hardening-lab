CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra
AR ?= ar

LIB_STATIC = libops.a
TARGET_DYN = app_dyn
TARGET_STATIC = app_static

.PHONY: all run-dyn run-static compare clean

all: $(LIB_STATIC) $(TARGET_DYN) $(TARGET_STATIC)

$(LIB_STATIC): libops.c
	$(CC) $(CFLAGS) -c $< -o libops.o
	$(AR) rcs $@ libops.o

$(TARGET_DYN): app.c $(LIB_STATIC)
	$(CC) $(CFLAGS) app.c -L. -lops -o $@

$(TARGET_STATIC): app.c $(LIB_STATIC)
	$(CC) $(CFLAGS) -static app.c -L. -lops -o $@

run-dyn: $(TARGET_DYN)
	@echo "=== [1] Running Dynamically Linked Binary ==="
	./$(TARGET_DYN)
	@echo ""
	@echo "=== Dependencies (ldd app_dyn) ==="
	ldd $(TARGET_DYN)

run-static: $(TARGET_STATIC)
	@echo "=== [2] Running Statically Linked Binary (Self-Contained) ==="
	./$(TARGET_STATIC)
	@echo ""
	@echo "=== Dependencies (ldd app_static) ==="
	-ldd $(TARGET_STATIC)

compare: all
	@echo "=== [Binary Metadata Comparison] ==="
	file $(TARGET_DYN)
	file $(TARGET_STATIC)
	@echo ""
	@echo "=== [Binary File Sizes] ==="
	ls -lh $(TARGET_DYN) $(TARGET_STATIC)

clean:
	rm -f $(LIB_STATIC) libops.o $(TARGET_DYN) $(TARGET_STATIC)
