package util

import (
	"net"
	"testing"
)

func TestIntToIPv4(t *testing.T) {
	// 127.0.0.1 in little endian (0x0100007f)
	ip := IntToIPv4(0x0100007f)
	expected := net.IPv4(127, 0, 0, 1).To4()
	if !ip.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, ip)
	}

	// 192.168.1.10 in network order: 10, 1, 168, 192 -> 0x0a01a8c0 little endian
	ip2 := IntToIPv4(0x0a01a8c0)
	expected2 := net.IPv4(192, 168, 1, 10).To4()
	if !ip2.Equal(expected2) {
		t.Fatalf("expected %v, got %v", expected2, ip2)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tc := range tests {
		got := FormatBytes(tc.bytes)
		if got != tc.expected {
			t.Errorf("FormatBytes(%d) = %s; want %s", tc.bytes, got, tc.expected)
		}
	}
}

func TestDefaultInterface(t *testing.T) {
	iface, err := DefaultInterface()
	if err != nil {
		t.Skipf("no active interface found: %v", err)
	}
	if iface == "" {
		t.Fatal("expected non-empty interface name")
	}
}
