package bpf

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/azusachino/cinnamon/pkg/util"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var protoNames = map[uint32]string{
	0: "OTHER",
	1: "TCP",
	2: "UDP",
	3: "ICMP",
}

// RunXDP loads the XDP packet counter program, attaches it to the specified
// interface, and polls statistics every interval until ctx is cancelled.
func RunXDP(ctx context.Context, ifaceName string, interval time.Duration) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q lookup failed: %w", ifaceName, err)
	}

	objs := bpfXdpObjects{}
	if err := loadBpfXdpObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading XDP bpf objects: %w", err)
	}
	defer objs.Close()

	// Attach XDP program to the network interface.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP to %s: %w", ifaceName, err)
	}
	defer l.Close()

	fmt.Printf("[cinnamon/xdp] Attached XDP packet counter to %s (index %d)\n", ifaceName, iface.Index)
	fmt.Printf("[cinnamon/xdp] Polling protocol statistics every %v (Ctrl-C to stop)...\n\n", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n[cinnamon/xdp] Detaching XDP hook...")
			return nil
		case t := <-ticker.C:
			fmt.Printf("--- [%s] Interface: %s ---\n", t.Format("15:04:05"), ifaceName)
			// Read protocol stats array map
			var key uint32
			var stats bpfXdpPktStats
			for key = 0; key < 4; key++ {
				name := protoNames[key]
				if err := objs.ProtoStatsMap.Lookup(key, &stats); err == nil {
					fmt.Printf("  %-8s: %10d pkts | %s\n", name, stats.Packets, util.FormatBytes(stats.Bytes))
				}
			}

			// Iterate top source IPs in LRU hash map
			var ipKey uint32
			var ipStats bpfXdpPktStats
			iter := objs.SrcIpMap.Iterate()
			topCount := 0
			fmt.Println("  Recent Active Source IPs:")
			for iter.Next(&ipKey, &ipStats) && topCount < 5 {
				ip := util.IntToIPv4(ipKey)
				fmt.Printf("    %-16s -> %8d pkts (%s)\n", ip.String(), ipStats.Packets, util.FormatBytes(ipStats.Bytes))
				topCount++
			}
			if topCount == 0 {
				fmt.Println("    (no active IPv4 traffic recorded yet)")
			}
			fmt.Println()
		}
	}
}
