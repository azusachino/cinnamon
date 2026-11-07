# Cinnamon Architecture Specification

## 1. Design Philosophy

Cinnamon is designed around three architectural principles:

1. **Ahead-of-Time (AOT) Hermetic Compilation:**
   eBPF C programs are compiled into native eBPF ELF bytecode using `clang` during development. The compiled bytecode is embedded directly into Go binary artifacts via `bpf2go`, removing any runtime dependency on LLVM, C toolchains, or kernel headers in production.

2. **Zero-Copy High-Throughput Streaming:**
   Event transport between kernel space and user space utilizes modern Linux **Ring Buffers** (`BPF_MAP_TYPE_RINGBUF`). Unlike legacy perf buffers, ring buffers use memory-mapped pages shared between kernel and user space, eliminating per-CPU memory overhead and event drops.

3. **Type-Safe User-Kernel Contracts:**
   `bpf2go` extracts C struct definitions and BPF map types from the ELF BTF data and generates strongly typed Go structs (`bpfXdpPktStats`, `bpfExecveExecEvent`, `bpfTcpTcpEvent`). Userspace code interacts with maps and ring buffers using generated Go structs without unsafe pointer casting.

---

## 2. Technology Comparison

| Dimension | Python BCC | Libbpf (C/C++) | Cilium/ebpf (Cinnamon) |
| :--- | :--- | :--- | :--- |
| **Control Plane** | Python interpreter + ctypes | C/C++ native binary | Pure Go native binary |
| **Compilation Time** | Runtime JIT (seconds) | Compile time (AOT) | Compile time (AOT via `bpf2go`) |
| **Target Dependencies** | Clang, LLVM, kernel-headers | `libbpf.so`, libc | Single static Go binary |
| **eBPF Syscall Implementation** | C libbcc wrapper | C libbpf wrapper | Pure Go `golang.org/x/sys/unix` |
| **Portability** | Low (breaks on kernel header drift) | High (with CO-RE) | High (with CO-RE and BTF) |
| **Event Overhead** | High (Python GIL, string parsing) | Extremely low | Low (Go runtime GC, zero-copy ringbuf) |

---

## 3. Subsystem Breakdown

### 3.1 XDP Packet Filtering & Protocol Counter (`bpf/xdp_counter.c`)

- **Hook Point:** `SEC("xdp")`
- **Execution Timing:** Executed inside the network device driver right when the packet arrives from the NIC DMA ring, **before** the Linux kernel allocates a `struct sk_buff` (socket buffer).
- **Processing Flow:**
  1. Validate pointer bounds: ensures `ctx->data + sizeof(struct ethhdr) <= ctx->data_end`.
  2. Parse Ethernet frame header (`eth->h_proto`).
  3. If IPv4 (`ETH_P_IP`), inspect `struct iphdr` protocol field.
  4. Increment `proto_stats_map` (Array Map, keys: `0=OTHER`, `1=TCP`, `2=UDP`, `3=ICMP`) atomically using `__sync_fetch_and_add`.
  5. Update `src_ip_map` (LRU Hash Map) with source IP and packet/byte counters.
  6. Return `XDP_PASS` to let packet continue normal network stack traversal.

### 3.2 Process Execution Tracing (`bpf/execve_tracer.c`)

- **Hook Point:** `SEC("kprobe/sys_execve")`
- **Execution Timing:** Fired upon entry into the `sys_execve` kernel function when any process executes a new binary.
- **Processing Flow:**
  1. Extract current process credentials via helper functions:
     - `bpf_get_current_pid_tgid()` -> PID/TGID
     - `bpf_get_current_uid_gid()` -> UID
     - `bpf_get_current_comm()` -> Task command name
  2. Reserve space in the 16 MB kernel ring buffer: `bpf_ringbuf_reserve(&exec_events, sizeof(struct exec_event), 0)`.
  3. Populate event payload.
  4. Submit to userspace poller: `bpf_ringbuf_submit(ev, 0)`.

### 3.3 Outbound TCP Latency Tracing (`bpf/tcp_tracer.c`)

- **Hook Points:** `SEC("kprobe/tcp_v4_connect")` and `SEC("kretprobe/tcp_v4_connect")`
- **Latency Measurement Mechanism:**
  1. On entry (`kprobe`):
     - Read start timestamp `ts = bpf_ktime_get_ns()`.
     - Read destination IP and port from `(struct sockaddr_in *)PT_REGS_PARM2(ctx)` via `bpf_probe_read_kernel`.
     - Save `struct conn_info` into `start_map` hash map keyed by `pid_tgid`.
  2. On return (`kretprobe`):
     - Lookup `start_map` using current `pid_tgid`.
     - Calculate elapsed time: `duration_ns = bpf_ktime_get_ns() - info->start_ts`.
     - Extract syscall return code: `ret = PT_REGS_RC(ctx)`.
     - Emit `struct tcp_event` into ring buffer `tcp_events`.
     - Delete entry from `start_map` to prevent memory leaks.

---

## 4. The bpf2go Generation Pipeline

The generation pipeline works as follows:

```
[bpf/*.c source]
       |
       v (clang -target bpf -O2 -g)
[ELF Bytecode (*.o)]
       |
       v (bpf2go analysis of BTF & ELF symbols)
[Generated Go Bindings (*_bpfel.go)]
  - Embeds ELF bytes via //go:embed
  - Emits Go structs for C types
  - Emits Program & Map accessor methods
       |
       v (go build ./cmd/cinnamon)
[Single Self-Contained Binary: bin/cinnamon]
```
