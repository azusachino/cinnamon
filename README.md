# cinnamon

> Modern eBPF practice workspace: kernel tracing, XDP packet filters, and Go `cilium/ebpf` probes.

[![Go Check](https://img.shields.io/badge/go-1.24%2B-blue.svg)](https://golang.org)
[![eBPF](https://img.shields.io/badge/eBPF-cilium%2Febpf-orange.svg)](https://github.com/cilium/ebpf)
[![License](https://img.shields.io/badge/license-MIT%2FGPL-green.svg)](LICENSE)

**cinnamon** is a personal learning lab and executable foundation for Linux kernel observability, high-performance networking, and systems performance engineering using eBPF and Go.

It evolves past runtime-interpreted Python BCC by establishing an Ahead-of-Time (AOT) compiled Go architecture powered by `cilium/ebpf` and `bpf2go`.

---

## Practice Tracks

| Track | Hook Point | Mechanism | BPF Map Type | Userspace CLI |
| :--- | :--- | :--- | :--- | :--- |
| **1. NIC-Layer Filtering** | `SEC("xdp")` | Driver / Hardware hook inspecting raw Ethernet frames | `BPF_MAP_TYPE_ARRAY` & `BPF_MAP_TYPE_LRU_HASH` | `cinnamon xdp -i <iface>` |
| **2. Syscall Tracing** | `SEC("kprobe/sys_execve")` | Kernel dynamic probe on process creation | `BPF_MAP_TYPE_RINGBUF` (Zero-copy 16MB) | `cinnamon execve` |
| **3. Socket Latency** | `SEC("kprobe/tcp_v4_connect")` & `kretprobe` | Measuring outbound TCP handshake latency | `BPF_MAP_TYPE_HASH` & `BPF_MAP_TYPE_RINGBUF` | `cinnamon tcp` |
| **4. BCC Prototyping** | `kprobe` (Python) | Runtime JIT compilation via BCC | `bpf_trace_printk` | `python/bcc_execve.py` |

---

## Architecture Overview

```
                      +---------------------------------------+
                      |          Userspace (Go CLI)           |
                      |  cmd/cinnamon  |  pkg/bpf  |  pkg/util|
                      +---------------------------------------+
                                          |
                      cilium/ebpf         |  bpf() syscall (Maps & Links)
                      bpf2go Bindings     v
   =============================================================================
   Linux Kernel Space
   -----------------------------------------------------------------------------
        [ Network Driver ]            [ Syscall Interface ]     [ TCP Stack ]
                |                               |                     |
        SEC("xdp")                      SEC("kprobe")         SEC("kprobe/kret")
        xdp_count_packets               kprobe_execve         tcp_v4_connect
                |                               |                     |
                v                               v                     v
      +--------------------+          +-------------------+ +-------------------+
      | proto_stats_map    |          | exec_events       | | start_map (Hash)  |
      | src_ip_map (LRU)   |          | (Ring Buffer)     | | tcp_events (Ring) |
      +--------------------+          +-------------------+ +-------------------+
   =============================================================================
```

For detailed design notes, see [`docs/architecture.md`](docs/architecture.md).

---

## Quickstart

### Prerequisites

- Linux kernel 5.8+ (for `BPF_MAP_TYPE_RINGBUF` and modern XDP hooks)
- `clang` & `llvm-strip`
- Go 1.24+ (managed via `mise` or system package)

### 1. Build & Run Tests

```bash
# Verify code formatting, vetting, and ELF spec validation
make check

# Build the unified cinnamon CLI binary
make build
```

### 2. Run eBPF Probes (requires root/sudo)

```bash
# 1. Real-time XDP packet and protocol statistics
sudo ./bin/cinnamon xdp -i eth0 -interval 1s

# 2. Trace all process executions in real time
sudo ./bin/cinnamon execve

# 3. Trace outbound TCP connections and kernel handshake latency
sudo ./bin/cinnamon tcp
```

---

## Development

All C eBPF kernel programs reside in `bpf/`. After modifying any `.c` source file, recompile bytecode and generate Go bindings:

```bash
make generate
make check
```

---

## Learning Notes & References

- [Practice Guide & Labs](docs/practice-guide.md)
- [Cilium eBPF Documentation](https://ebpf-go.dev/)
- [Apricot Systems Performance Course](file:///home/haru/Projects/project-github/harus-workstation/vendor/apricot/courses/computer-science/systems-performance/index.md)
