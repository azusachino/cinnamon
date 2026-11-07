package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// RunExecve loads the execve kprobe tracer and streams process executions
// from kernel ring buffer to stdout until ctx is cancelled.
func RunExecve(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	objs := bpfExecveObjects{}
	if err := loadBpfExecveObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading execve bpf objects: %w", err)
	}
	defer objs.Close()

	// Open kprobe on sys_execve
	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		return fmt.Errorf("opening sys_execve kprobe: %w", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.ExecEvents)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	fmt.Println("[cinnamon/execve] Attached kprobe to sys_execve")
	fmt.Printf("%-10s  %-8s  %-6s  %s\n", "TIME", "PID", "UID", "COMM")
	fmt.Println("--------------------------------------------------")

	var ev bpfExecveExecEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("\n[cinnamon/execve] Stopped tracing execve.")
				return nil
			}
			return fmt.Errorf("reading ringbuf: %w", err)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		now := time.Now().Format("15:04:05")
		comm := unix.ByteSliceToString(ev.Comm[:])
		fmt.Printf("%-10s  %-8d  %-6d  %s\n", now, ev.Pid, ev.Uid, comm)
	}
}
