# NegativeClaw Makefile
# Minimal AI Agent in x86-64 Assembly
# Target: Linux x86-64, no libc

# Assembler and linker
NASM = nasm
LD = ld

# Flags
NASMFLAGS = -f elf64 -g -F dwarf
LDFLAGS = -nostdlib -static

# Source files
SRCS = src/main.asm \
       src/sha256.asm \
       src/x25519.asm \
       src/chacha20poly.asm \
       src/tls13.asm

# Object files
OBJS = $(SRCS:.asm=.o)

# Output
TARGET = negative_claw

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^
	@echo "Binary size:"
	@ls -la $(TARGET)
	@size $(TARGET) 2>/dev/null || true

# Assemble
%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

# Clean
clean:
	rm -f $(OBJS) $(TARGET)

# Strip symbols for smallest binary
strip: $(TARGET)
	strip -s $(TARGET)
	@echo "Stripped binary size:"
	@ls -la $(TARGET)

# Disassemble for inspection
disasm: $(TARGET)
	objdump -d -M intel $(TARGET) > $(TARGET).dis

# Size analysis
size: $(TARGET)
	@echo "=== Section sizes ==="
	@size $(TARGET)
	@echo ""
	@echo "=== Object file sizes ==="
	@for f in $(OBJS); do \
		echo -n "$$f: "; \
		ls -la $$f | awk '{print $$5}' ; \
	done
	@echo ""
	@echo "=== Total binary size ==="
	@ls -la $(TARGET) | awk '{print $$5 " bytes"}'

.PHONY: all clean strip disasm size
