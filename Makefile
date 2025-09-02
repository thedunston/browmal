# Browmal WebAssembly Build Makefile
# Builds the binary analysis tool for browser deployment

# Variables
GOOS = js
GOARCH = wasm
SRC_DIR = src
MAIN_GO = $(SRC_DIR)/main.go
WASM_OUTPUT = main.wasm
B64_OUTPUT = main.wasm.b64

# Default target.
.PHONY: all
all: build convert update-html

# Build the WebAssembly binary.
.PHONY: build
build:
	@echo "Building WebAssembly binary..."
	cd $(SRC_DIR) && GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-s -w" -o ../$(WASM_OUTPUT) $(notdir $(MAIN_GO))
	@echo "Build complete: $(WASM_OUTPUT)"

# Convert WASM to base64 and format on single line.
.PHONY: convert
convert: build
	@echo "Converting WASM to base64..."
	base64 -w 0 $(WASM_OUTPUT) > $(B64_OUTPUT)
	@echo "Base64 conversion complete: $(B64_OUTPUT)"

# Update index.html with new WASM base64 data.
.PHONY: update-html
update-html: convert
	@echo "Updating index.html with new WASM base64 data..."
	@if [ ! -f $(B64_OUTPUT) ]; then \
		echo "Error: $(B64_OUTPUT) not found"; \
		exit 1; \
	fi
	@python3 -c "\
import re; \
wasm_b64 = open('$(B64_OUTPUT)').read().strip(); \
html = open('index.html').read(); \
new_html = re.sub(r'const wasmBase64 = \"[^\"]*\"', f'const wasmBase64 = \"{wasm_b64}\"', html); \
open('index.html', 'w').write(new_html)"
	@echo "index.html updated with new WASM data"

# Clean build artifacts.
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(WASM_OUTPUT) $(B64_OUTPUT)
	@echo "Clean complete"

# Rebuild everything from scratch.
.PHONY: rebuild
rebuild: clean all

# Show file sizes.
.PHONY: info
info:
	@echo "Build information:"
	@if [ -f $(WASM_OUTPUT) ]; then \
		echo "  WASM size: $$(du -h $(WASM_OUTPUT) | cut -f1)"; \
	else \
		echo "  WASM file not found"; \
	fi
	@if [ -f $(B64_OUTPUT) ]; then \
		echo "  Base64 size: $$(du -h $(B64_OUTPUT) | cut -f1)"; \
		echo "  Base64 lines: $$(wc -l < $(B64_OUTPUT))"; \
	else \
		echo "  Base64 file not found"; \
	fi

# Help target.
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all        - Build WASM, convert to base64, and update HTML (default)"
	@echo "  build      - Build WebAssembly binary only"
	@echo "  convert    - Convert existing WASM to base64"
	@echo "  update-html - Update index.html with new WASM base64 data"
	@echo "  clean      - Remove build artifacts"
	@echo "  rebuild    - Clean and build everything"
	@echo "  info       - Show file size information"
	@echo "  help       - Show this help message"
