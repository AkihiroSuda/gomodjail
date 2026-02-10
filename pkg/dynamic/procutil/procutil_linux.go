package procutil

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

func ReadUint64(pid int, addr uintptr) (uint64, error) {
	buf := make([]byte, 8)
	if _, err := unix.PtracePeekData(pid, addr, buf); err != nil {
		return 0, fmt.Errorf("failed to read 0x%x (%d bytes) from PID %d", addr, len(buf), pid)
	}
	return binary.NativeEndian.Uint64(buf), nil
}

func ReadString(pid int, addr uintptr, bufSize int) (string, error) {
	if addr == 0 {
		return "", nil
	}
	buf := make([]byte, bufSize)
	c, err := unix.PtracePeekData(pid, addr, buf)
	if err != nil {
		return "", fmt.Errorf("failed to read 0x%x (%d bytes) from PID %d", addr, bufSize, pid)
	}
	buf = buf[:c]
	nilIdx := strings.Index(string(buf), "\x00")
	if nilIdx < 0 {
		return "", fmt.Errorf("nil byte was not found in the %d bytes", c)
	}
	return string(buf[:nilIdx]), nil
}

func WaitForStopSignal(pid int) (int, unix.Signal, error) {
	var ws unix.WaitStatus
	wPid, err := unix.Wait4(pid, &ws, unix.WALL, nil)
	if err != nil {
		return 0, 0, err
	}
	if !ws.Stopped() {
		return 0, 0, fmt.Errorf("expected to be stopped (wPid=%d, ws=0x%x)", wPid, ws)
	}
	return wPid, ws.StopSignal(), nil
}
