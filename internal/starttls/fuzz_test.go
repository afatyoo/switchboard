package starttls

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// limitedWriter fails once the proxy has written more than max bytes, which
// would mean an unbounded response to a hostile client.
type limitedWriter struct {
	n, max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	if w.n > w.max {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// fuzzClient feeds arbitrary client bytes to a protocol's pre-TLS dialogue and
// checks the safety properties that matter on the internet-facing side.
func fuzzClient(t *testing.T, p Protocol, data []byte, startVerbs ...string) {
	r := bufio.NewReaderSize(bytes.NewReader(data), 1024)
	w := &limitedWriter{max: 64 * 1024}
	err := p.Client(r, w, "mail.provider.test")
	if w.n > w.max {
		t.Fatalf("response too large: %d bytes", w.n)
	}
	if err != nil {
		return
	}
	// STARTTLS was accepted: nothing may be left over (command injection),
	// and the input must really contain a STARTTLS command.
	if r.Buffered() != 0 {
		t.Fatalf("accepted STARTTLS with %d bytes still buffered", r.Buffered())
	}
	up := strings.ToUpper(string(data))
	found := false
	for _, v := range startVerbs {
		if strings.Contains(up, v) {
			found = true
		}
	}
	if !found {
		t.Fatalf("accepted STARTTLS without a STARTTLS command in %q", data)
	}
}

func FuzzSMTPClient(f *testing.F) {
	for _, s := range []string{
		"EHLO x\r\nSTARTTLS\r\n",
		"HELO x\r\nNOOP\r\nSTARTTLS\r\n",
		"STARTTLS\r\nMAIL FROM:<a@b>\r\n",
		"AUTH PLAIN AGFAYg==\r\n",
		"\x16\x03\x01\x02\x00\x01",
		strings.Repeat("A", 600) + "\r\n",
		"QUIT\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzClient(t, smtp{}, data, "STARTTLS") })
}

func FuzzIMAPClient(f *testing.F) {
	for _, s := range []string{
		"a CAPABILITY\r\nb STARTTLS\r\n",
		"a LOGIN u p\r\n",
		"a STARTTLS\r\nb LOGIN u p\r\n",
		"x\r\n",
		"* * * *\r\n",
		"\x16\x03\x03",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzClient(t, imap{}, data, "STARTTLS") })
}

func FuzzPOP3Client(f *testing.F) {
	for _, s := range []string{
		"CAPA\r\nSTLS\r\n",
		"USER u\r\nPASS p\r\n",
		"STLS\r\nUSER u\r\n",
		"\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzClient(t, pop3{}, data, "STLS") })
}

// The upstream parsers only talk to Carbonio, but a broken or hostile
// upstream must not crash the proxy or make it read forever.
func FuzzUpstream(f *testing.F) {
	for _, s := range []string{
		"220 x\r\n250-x\r\n250 STARTTLS\r\n220 go\r\n",
		"* OK x\r\nsb1 OK go\r\n",
		"+OK x\r\n+OK go\r\n",
		"250\r\n",
		"\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, p := range []Protocol{smtp{}, imap{}, pop3{}} {
			r := bufio.NewReaderSize(bytes.NewReader(data), 4096)
			_ = p.Upstream(r, io.Discard)
		}
	})
}
