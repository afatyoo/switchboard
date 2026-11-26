package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
)

// DefaultMaxJSONBytes caps ReadJSONSafe when maxBytes is zero or negative.
const DefaultMaxJSONBytes int64 = 1 << 20

// ReadJSONSafe reads JSON into v from a file that may sit in a directory
// writable by a less privileged user. It refuses symlinks (O_NOFOLLOW), does
// not block on FIFOs (O_NONBLOCK), requires a regular file, checks the owner
// when wantUID >= 0 and refuses files larger than maxBytes. A missing file
// returns an error wrapping os.ErrNotExist.
func ReadJSONSafe(path string, maxBytes int64, wantUID int, v any) error {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxJSONBytes
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if wantUID >= 0 {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot determine owner", path)
		}
		if int(st.Uid) != wantUID {
			return fmt.Errorf("%s: owned by uid %d, want %d", path, st.Uid, wantUID)
		}
	}
	if fi.Size() > maxBytes {
		return fmt.Errorf("%s: %d bytes exceeds limit of %d", path, fi.Size(), maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(b)) > maxBytes {
		return fmt.Errorf("%s: exceeds limit of %d bytes", path, maxBytes)
	}
	return json.Unmarshal(b, v)
}
