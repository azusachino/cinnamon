// Package bpf provides eBPF program bindings and runtime loaders.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf" bpfXdp ../../bpf/xdp_counter.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf" bpfExecve ../../bpf/execve_tracer.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf" bpfTcp ../../bpf/tcp_tracer.c
