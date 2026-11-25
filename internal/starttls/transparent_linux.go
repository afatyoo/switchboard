package starttls

import "syscall"

// transparentControl sets IP_TRANSPARENT so the upstream connection can use
// the client's IP as source address (needs CAP_NET_ADMIN and TPROXY routing).
func transparentControl(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
