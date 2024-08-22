TINYGO ?= tinygo

.PHONY: all
all: wasm_exec.js wasm.wasm

wasm.wasm: main.go
	$(TINYGO) build -o wasm.wasm main.go

wasm_exec.js:
	cp $(shell $(TINYGO) env TINYGOROOT)/targets/wasm_exec.js .


run:
	python -m http.server

.PHONY: clean
clean:
	rm -f wasm.wasm wasm_exec.js
