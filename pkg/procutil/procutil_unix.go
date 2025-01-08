package procutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

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
