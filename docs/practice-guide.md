# Cinnamon eBPF Practice Guide & Labs

This guide outlines hands-on exercises for learning and experimenting with eBPF using Cinnamon.

---

## Lab 1: XDP Packet Counter & Network Interface Inspection

### Objective
Understand the execution model of eXpress Data Path (XDP) at the device driver layer and read statistics from BPF array and LRU hash maps.

### Steps
1. Identify your active network interface:
   ```bash
   ip -brief link
   ```
2. Start the XDP packet counter:
   ```bash
   sudo ./bin/cinnamon xdp -i eth0 -interval 1s
   ```
3. In another terminal, generate diverse network traffic:
   ```bash
   # Ping traffic (ICMP)
   ping -c 5 1.1.1.1

   # DNS traffic (UDP)
   dig @8.8.8.8 google.com

   # HTTP/HTTPS traffic (TCP)
   curl -I https://www.kernel.org
   ```
4. Observe the real-time protocol breakdown (`TCP`, `UDP`, `ICMP`, `OTHER`) and top active source IPv4 addresses in Cinnamon's output.

### Code Exploration
- Inspect `bpf/xdp_counter.c`: Note how bounds checking `(void *)(eth + 1) > data_end` is strictly required by the eBPF kernel verifier. Try removing a bounds check and running `make generate` to see the verifier rejection.

---

## Lab 2: Process Execution Tracing with Ring Buffers

### Objective
Trace syscalls using dynamic kernel probes (`kprobe`), extract process credentials, and stream structured events to userspace via zero-copy ring buffers.

### Steps
1. Start the execve tracer:
   ```bash
   sudo ./bin/cinnamon execve
   ```
2. In another terminal, trigger multiple commands:
   ```bash
   ls -la /tmp
   git status
   python3 -c "print('hello')"
   ```
3. Watch the stream of events showing timestamp, process ID (`PID`), user ID (`UID`), and executable name (`COMM`).

### Code Exploration
- Look at `bpf/execve_tracer.c`: See `bpf_ringbuf_reserve` and `bpf_ringbuf_submit`.
- Check `pkg/bpf/execve.go`: Notice how `ringbuf.Reader` blocks until kernel data is available and handles graceful shutdown when context is cancelled.

---

## Lab 3: Measuring TCP Connection Latency with Kretprobes

### Objective
Pair entry probes (`kprobe`) and return probes (`kretprobe`) with a hash map to measure kernel function latency without modifying application code.

### Steps
1. Launch the TCP tracer:
   ```bash
   sudo ./bin/cinnamon tcp
   ```
2. Trigger TCP connections across varying network distances:
   ```bash
   # Local connection (sub-millisecond latency)
   curl -I http://127.0.0.1:8080 || true

   # Remote connection (WAN latency)
   curl -I https://github.com
   ```
3. Inspect the printed connection latency and destination IP/port.

### Code Exploration
- Review `bpf/tcp_tracer.c`: Observe the two-phase correlation pattern:
  1. Entry probe stores timestamp in `start_map` using PID/TGID as the correlation key.
  2. Exit probe calculates duration and cleans up the key from `start_map` to prevent map leaks.

---

## Lab 4: Comparative Prototyping with BCC and bpftrace

### Objective
Compare Ahead-of-Time Go compilation against dynamic BCC and bpftrace scripts.

### Steps
1. Run the Python BCC script:
   ```bash
   sudo uv run python/bcc_execve.py
   ```
2. Run a one-line bpftrace probe:
   ```bash
   sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s (%d)\n", comm, pid); }'
   ```
3. Evaluate the trade-offs: bpftrace is ideal for rapid 1-minute ad-hoc investigations; Cinnamon (Go + `cilium/ebpf`) is ideal for robust production monitoring and long-lived observability agents.
