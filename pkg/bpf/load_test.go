package bpf

import (
	"testing"
)

func TestLoadBpfSpecs(t *testing.T) {
	xdpSpec, err := loadBpfXdp()
	if err != nil {
		t.Fatalf("loadBpfXdp failed: %v", err)
	}
	if xdpSpec == nil {
		t.Fatal("xdpSpec is nil")
	}
	if _, ok := xdpSpec.Programs["xdp_count_packets"]; !ok {
		t.Fatal("xdp_count_packets program not found in xdpSpec")
	}
	if _, ok := xdpSpec.Maps["proto_stats_map"]; !ok {
		t.Fatal("proto_stats_map not found in xdpSpec")
	}
	if _, ok := xdpSpec.Maps["src_ip_map"]; !ok {
		t.Fatal("src_ip_map not found in xdpSpec")
	}

	execveSpec, err := loadBpfExecve()
	if err != nil {
		t.Fatalf("loadBpfExecve failed: %v", err)
	}
	if execveSpec == nil {
		t.Fatal("execveSpec is nil")
	}
	if _, ok := execveSpec.Programs["kprobe_execve"]; !ok {
		t.Fatal("kprobe_execve program not found in execveSpec")
	}
	if _, ok := execveSpec.Maps["exec_events"]; !ok {
		t.Fatal("exec_events map not found in execveSpec")
	}

	tcpSpec, err := loadBpfTcp()
	if err != nil {
		t.Fatalf("loadBpfTcp failed: %v", err)
	}
	if tcpSpec == nil {
		t.Fatal("tcpSpec is nil")
	}
	if _, ok := tcpSpec.Programs["kprobe_tcp_v4_connect"]; !ok {
		t.Fatal("kprobe_tcp_v4_connect program not found in tcpSpec")
	}
	if _, ok := tcpSpec.Programs["kretprobe_tcp_v4_connect"]; !ok {
		t.Fatal("kretprobe_tcp_v4_connect program not found in tcpSpec")
	}
	if _, ok := tcpSpec.Maps["start_map"]; !ok {
		t.Fatal("start_map not found in tcpSpec")
	}
	if _, ok := tcpSpec.Maps["tcp_events"]; !ok {
		t.Fatal("tcp_events ringbuf not found in tcpSpec")
	}
}
