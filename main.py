from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!\\n");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name=b"hello")

print("Tracing execve syscalls... Hit Ctrl-C to end.")
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\nDetaching...")
