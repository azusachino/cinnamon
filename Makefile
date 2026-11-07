GO ?= go
GOFMT ?= gofmt

.PHONY: all help generate build fmt fmt-check lint test check clean run-xdp run-execve run-tcp

all: check build

help:
	@echo "cinnamon - modern eBPF learning lab & kernel probes"
	@echo ""
	@echo "Available targets:"
	@echo "  make generate    - Compile C BPF programs and generate Go bindings via bpf2go"
	@echo "  make build       - Build the cinnamon CLI binary (bin/cinnamon)"
	@echo "  make fmt         - Format Go code using gofmt"
	@echo "  make fmt-check   - Check Go code formatting"
	@echo "  make lint        - Run static analysis (go vet)"
	@echo "  make test        - Run unit tests with race detection"
	@echo "  make check       - Run all gates: fmt-check, lint, test"
	@echo "  make clean       - Remove built binaries and temporary artifacts"
	@echo "  make run-xdp     - Run XDP packet counter (requires sudo)"
	@echo "  make run-execve  - Run execve kprobe tracer (requires sudo)"
	@echo "  make run-tcp     - Run TCP connection latency tracer (requires sudo)"

generate:
	$(GO) generate ./...

build:
	@mkdir -p bin
	$(GO) build -o bin/cinnamon ./cmd/cinnamon

fmt:
	$(GOFMT) -w cmd pkg

fmt-check:
	@files="$$($(GOFMT) -l cmd pkg)" || exit $$?; if [ -n "$$files" ]; then printf '%s\n' "$$files"; exit 1; fi

lint:
	$(GO) vet ./...
	$(GO) mod verify

test:
	$(GO) test -v -race ./...

check: fmt-check lint test

clean:
	rm -rf bin/

run-xdp: build
	sudo ./bin/cinnamon xdp

run-execve: build
	sudo ./bin/cinnamon execve

run-tcp: build
	sudo ./bin/cinnamon tcp
