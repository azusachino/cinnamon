package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/azusachino/cinnamon/pkg/util"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// RunTCP attaches kprobe and kretprobe to tcp_v4_connect to track TCP connection
// establishment latency and destinations until ctx is cancelled.
func RunTCP(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	objs := bpfTcpObjects{}
	if err := loadBpfTcpObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading TCP bpf objects: %w", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		return fmt.Errorf("opening tcp_v4_connect kprobe: %w", err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("tcp_v4_connect", objs.KretprobeTcpV4Connect, nil)
	if err != nil {
		return fmt.Errorf("opening tcp_v4_connect kretprobe: %w", err)
	}
	defer krp.Close()

	rd, err := ringbuf.NewReader(objs.TcpEvents)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	fmt.Println("[cinnamon/tcp] Attached kprobe/kretprobe to tcp_v4_connect")
	fmt.Printf("%-10s  %-8s  %-16s  %-21s  %-10s  %s\n", "TIME", "PID", "COMM", "DESTINATION", "LATENCY", "RESULT")
	fmt.Println("----------------------------------------------------------------------------------------")

	var ev bpfTcpTcpEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("\n[cinnamon/tcp] Stopped tracing TCP connections.")
				return nil
			}
			return fmt.Errorf("reading ringbuf: %w", err)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		now := time.Now().Format("15:04:05")
		comm := unix.ByteSliceToString(ev.Comm[:])
		destIP := util.IntToIPv4(ev.Daddr)
		dest := net.JoinHostPort(destIP.String(), fmt.Sprintf("%d", ev.Dport))

		latency := time.Duration(ev.DurationNs) * time.Nanosecond
		status := "OK"
		if ev.RetVal < 0 {
			status = fmt.Sprintf("ERR(%d)", ev.RetVal)
		}

		fmt.Printf("%-10s  %-8d  %-16s  %-21s  %-10s  %s\n",
			now, ev.Pid, comm, dest, latency.Round(time.Microsecond), status)
	}
}
