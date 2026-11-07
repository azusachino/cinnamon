// Package util provides networking and formatting helpers for eBPF probes.
package util

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IntToIPv4 converts a network-byte-order uint32 to net.IP.
func IntToIPv4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

// DefaultInterface returns the name of the first active non-loopback network interface.
func DefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		return iface.Name, nil
	}

	// Fallback to loopback if no physical/virtual device is up
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no active network interface found")
}

// FormatBytes converts raw bytes count to human-readable format.
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
