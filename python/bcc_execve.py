#!/usr/bin/env python3
"""
Secondary / Prototyping Script: BCC execve kprobe tracer.
Compares dynamic BCC compilation with cinnamon's native Go + bpf2go architecture.
"""

from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello from BCC execve!\n");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name=b"hello")

print("Tracing execve syscalls with Python BCC... Hit Ctrl-C to end.")
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\nDetaching kprobe...")
