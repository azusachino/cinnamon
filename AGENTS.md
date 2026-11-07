# cinnamon — Agent Guide

Single source of truth for humans and AI agents working in this repository.

## Project Overview

**cinnamon** is a modern personal eBPF practice workspace and learning laboratory. It focuses on kernel observability, high-performance networking (XDP), syscall tracing, and socket performance using Go (`cilium/ebpf` + `bpf2go`) alongside C kernel probes, with secondary support for Python BCC and bpftrace scripts.

- `README.md` — overview, architecture, and quickstart commands
- `docs/architecture.md` — eBPF kernel/user space boundary, bpf2go compilation, and map architectures
- `docs/practice-guide.md` — step-by-step labs for XDP, kprobes, tracepoints, and ring buffers
- `Makefile` — canonical build, test, and verification gates

## Directory Layout

```text
bpf/                     C kernel eBPF programs
  headers/               Self-contained BPF definitions and helpers (cilium/ebpf standard)
  xdp_counter.c          XDP NIC-layer packet & byte counter with LRU hash map
  execve_tracer.c        Process execution kprobe tracer with ring buffer
  tcp_tracer.c           Outbound TCP connection latency kprobe/kretprobe tracer
cmd/
  cinnamon/main.go       Unified CLI tool with subcommands (xdp, execve, tcp, version)
pkg/
  bpf/                   Go control plane: loaders, map readers, ring buffer pollers
    gen.go               bpf2go generation directives
    xdp.go               XDP loader and real-time statistics poller
    execve.go            Execve kprobe loader and event streamer
    tcp.go               TCP tracer loader and latency calculator
  util/                  Networking and formatting utility helpers
python/
  bcc_execve.py          Preserved BCC Python script for comparative prototyping
  README.md              BCC vs cilium/ebpf architectural comparison
docs/                    Architecture specifications and hands-on practice guides
```

## Tech Stack & Tooling

- **Go:** 1.24+ (managed via `.mise.toml`)
- **eBPF Library:** `github.com/cilium/ebpf` (pure Go eBPF loader, no libbpf dependency at runtime)
- **Code Generator:** `bpf2go` (compiles C source to eBPF bytecode via `clang` and emits type-safe Go bindings)
- **C Compiler:** `clang` (supports `-target bpf`)
- **Python / BCC:** `uv`, Python 3.12+ (secondary prototyping only)

## Working Rules

- Keep Go code formatted with `gofmt` and clean according to `go vet`.
- When updating C kernel programs in `bpf/*.c`, always re-run `make generate` to regenerate the Go bindings and verified bytecode before testing.
- Unit tests must be fast and pass in unprivileged environments without requiring root or kernel probe capabilities (use `loadBpf*` collection spec validation).
- eBPF kernel code must adhere to eBPF verifier constraints: bounded loops, verified memory access, and NULL-check after map lookups.
- Before committing, always run the project verification gate:

```bash
make check
```
