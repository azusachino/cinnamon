package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/azusachino/cinnamon/pkg/bpf"
	"github.com/azusachino/cinnamon/pkg/util"
)

const version = "0.2.0"

func printUsage() {
	fmt.Fprintf(os.Stderr, `cinnamon - modern eBPF learning lab & kernel probes (v%s)

Usage:
  cinnamon <command> [options]

Commands:
  xdp        Count packets and protocols at NIC driver layer via XDP
  execve     Trace process executions via sys_execve kprobe and ring buffer
  tcp        Measure outbound TCP connection latency via tcp_v4_connect kprobe/kretprobe
  version    Show version and environment details
  help       Show this help message

Run 'cinnamon <command> -h' for command-specific flags.
Note: eBPF program attachment requires root privileges (sudo).
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cmd := os.Args[1]
	switch cmd {
	case "xdp":
		fs := flag.NewFlagSet("xdp", flag.ExitOnError)
		ifaceFlag := fs.String("i", "", "Network interface to attach XDP program (default: first active interface)")
		intervalFlag := fs.Duration("interval", 1*time.Second, "Polling interval for packet statistics")
		_ = fs.Parse(os.Args[2:])

		ifaceName := *ifaceFlag
		if ifaceName == "" {
			defaultIface, err := util.DefaultInterface()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error detecting default interface: %v\n", err)
				os.Exit(1)
			}
			ifaceName = defaultIface
		}

		if err := bpf.RunXDP(ctx, ifaceName, *intervalFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error running XDP: %v\n", err)
			os.Exit(1)
		}

	case "execve":
		if err := bpf.RunExecve(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error running execve tracer: %v\n", err)
			os.Exit(1)
		}

	case "tcp":
		if err := bpf.RunTCP(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error running TCP tracer: %v\n", err)
			os.Exit(1)
		}

	case "version":
		fmt.Printf("cinnamon v%s (Go + cilium/ebpf)\n", version)

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}
