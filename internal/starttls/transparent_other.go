//go:build !linux

package starttls

import (
	"errors"
	"syscall"
)

func transparentControl(network, address string, c syscall.RawConn) error {
	return errors.New("transparent mode is only supported on Linux")
}
