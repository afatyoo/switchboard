package starttls

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// errClose ends the session quietly (client said QUIT/LOGOUT).
var errClose = errors.New("client closed session")

// Protocol speaks the plain text part of a session until STARTTLS.
type Protocol interface {
	Name() string
	// Client runs the pre-TLS dialogue with the client. It returns nil when
	// the client asked for STARTTLS and was told to start the handshake.
	Client(r *bufio.Reader, w io.Writer, banner string) error
	// Upstream runs the pre-TLS dialogue with the real server and asks it
	// for STARTTLS. It returns nil when the server is ready for TLS.
	Upstream(r *bufio.Reader, w io.Writer) error
}

// ByName returns the protocol for smtp, imap or pop3.
func ByName(name string) (Protocol, error) {
	switch name {
	case "smtp":
		return smtp{}, nil
	case "imap":
		return imap{}, nil
	case "pop3":
		return pop3{}, nil
	}
	return nil, fmt.Errorf("unknown protocol %q", name)
}

const (
	maxLine     = 512
	maxCommands = 20
)

// ErrTLSOnPlainPort means the client started a TLS handshake on a STARTTLS
// port, usually a client set to "SSL/TLS" instead of "STARTTLS".
var ErrTLSOnPlainPort = errors.New("client sent a TLS handshake on a STARTTLS port: set the client to STARTTLS, or use the implicit TLS port (465, 993, 995)")

// readLine reads one CRLF or LF terminated line, refusing long lines.
func readLine(r *bufio.Reader) (string, error) {
	// 0x16 is the TLS handshake record type; no SMTP/IMAP/POP3 command starts
	// with it.
	if b, err := r.Peek(1); err == nil && b[0] == 0x16 {
		return "", ErrTLSOnPlainPort
	}
	var b strings.Builder
	for {
		frag, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		b.Write(frag)
		if b.Len() > maxLine {
			return "", errors.New("line too long")
		}
		if !isPrefix {
			return b.String(), nil
		}
	}
}

// noPipelinedData guards against STARTTLS command injection: nothing may
// follow the STARTTLS command in the plain text buffer, otherwise it would be
// treated as if it had arrived over TLS.
//
// Checking only the bufio buffer is enough. Bytes the client sent after
// STARTTLS that are still in the kernel socket buffer are read next by
// tls.Server as handshake records, so they fail the handshake; they are never
// forwarded upstream as plain text. Only the bufio buffer could hand pre-TLS
// bytes to the post-TLS side, because it is a separate reader dropped after
// this check (tls.Server reads the raw conn, not br). Keep it that way: never
// pass this reader, or anything wrapping it, to tls.Server or to the upstream
// copy.
func noPipelinedData(r *bufio.Reader) error {
	if r.Buffered() > 0 {
		return errors.New("data after STARTTLS, possible command injection")
	}
	return nil
}

func write(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}

// ---- SMTP (RFC 3207) ----

type smtp struct{}

func (smtp) Name() string { return "smtp" }

func (smtp) Client(r *bufio.Reader, w io.Writer, banner string) error {
	if err := write(w, "220 "+banner+" ESMTP\r\n"); err != nil {
		return err
	}
	for i := 0; i < maxCommands; i++ {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		verb, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			// No PIPELINING: commands must not be sent ahead of STARTTLS.
			err = write(w, "250-"+banner+"\r\n250 STARTTLS\r\n")
		case "HELO":
			err = write(w, "250 "+banner+"\r\n")
		case "STARTTLS":
			if err := noPipelinedData(r); err != nil {
				return err
			}
			return write(w, "220 2.0.0 Ready to start TLS\r\n")
		case "NOOP", "RSET":
			err = write(w, "250 2.0.0 OK\r\n")
		case "QUIT":
			_ = write(w, "221 2.0.0 Bye\r\n")
			return errClose
		default:
			err = write(w, "530 5.7.0 Must issue a STARTTLS command first\r\n")
		}
		if err != nil {
			return err
		}
	}
	_ = write(w, "421 4.7.0 Too many commands\r\n")
	return errors.New("too many commands before STARTTLS")
}

// smtpReply reads a (possibly multi-line) reply and returns code and lines.
func smtpReply(r *bufio.Reader) (string, []string, error) {
	var lines []string
	for {
		l, err := readLine(r)
		if err != nil {
			return "", nil, err
		}
		if len(l) < 4 {
			return "", nil, fmt.Errorf("bad SMTP reply %q", l)
		}
		lines = append(lines, l[4:])
		if l[3] == ' ' {
			return l[:3], lines, nil
		}
	}
}

func (smtp) Upstream(r *bufio.Reader, w io.Writer) error {
	if code, _, err := smtpReply(r); err != nil || code != "220" {
		return fmt.Errorf("upstream greeting %s: %v", code, err)
	}
	if err := write(w, "EHLO switchboard\r\n"); err != nil {
		return err
	}
	code, caps, err := smtpReply(r)
	if err != nil || code != "250" {
		return fmt.Errorf("upstream EHLO %s: %v", code, err)
	}
	ok := false
	for _, c := range caps {
		if strings.EqualFold(strings.TrimSpace(c), "STARTTLS") {
			ok = true
		}
	}
	if !ok {
		return errors.New("upstream does not offer STARTTLS")
	}
	if err := write(w, "STARTTLS\r\n"); err != nil {
		return err
	}
	if code, _, err := smtpReply(r); err != nil || code != "220" {
		return fmt.Errorf("upstream STARTTLS %s: %v", code, err)
	}
	return nil
}

// ---- IMAP (RFC 3501 section 6.2.1) ----

type imap struct{}

func (imap) Name() string { return "imap" }

const imapCaps = "IMAP4rev1 STARTTLS LOGINDISABLED"

func (imap) Client(r *bufio.Reader, w io.Writer, banner string) error {
	if err := write(w, "* OK [CAPABILITY "+imapCaps+"] "+banner+" ready\r\n"); err != nil {
		return err
	}
	for i := 0; i < maxCommands; i++ {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			err = write(w, "* BAD Invalid command\r\n")
			if err != nil {
				return err
			}
			continue
		}
		tag, cmd := f[0], strings.ToUpper(f[1])
		switch cmd {
		case "CAPABILITY":
			err = write(w, "* CAPABILITY "+imapCaps+"\r\n"+tag+" OK CAPABILITY completed\r\n")
		case "NOOP":
			err = write(w, tag+" OK NOOP completed\r\n")
		case "LOGOUT":
			_ = write(w, "* BYE Logging out\r\n"+tag+" OK LOGOUT completed\r\n")
			return errClose
		case "STARTTLS":
			if err := noPipelinedData(r); err != nil {
				return err
			}
			return write(w, tag+" OK Begin TLS negotiation now\r\n")
		case "LOGIN", "AUTHENTICATE":
			err = write(w, tag+" NO [PRIVACYREQUIRED] Use STARTTLS first\r\n")
		default:
			err = write(w, tag+" BAD Use STARTTLS first\r\n")
		}
		if err != nil {
			return err
		}
	}
	_ = write(w, "* BYE Too many commands\r\n")
	return errors.New("too many commands before STARTTLS")
}

func (imap) Upstream(r *bufio.Reader, w io.Writer) error {
	g, err := readLine(r)
	if err != nil || !strings.HasPrefix(g, "* OK") {
		return fmt.Errorf("upstream greeting %q: %v", g, err)
	}
	if err := write(w, "sb1 STARTTLS\r\n"); err != nil {
		return err
	}
	for i := 0; i < maxCommands; i++ {
		l, err := readLine(r)
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, "sb1 ") {
			if strings.HasPrefix(strings.ToUpper(l), "SB1 OK") {
				return nil
			}
			return fmt.Errorf("upstream STARTTLS: %q", l)
		}
	}
	return errors.New("upstream STARTTLS: no tagged reply")
}

// ---- POP3 (RFC 2595 section 4) ----

type pop3 struct{}

func (pop3) Name() string { return "pop3" }

func (pop3) Client(r *bufio.Reader, w io.Writer, banner string) error {
	if err := write(w, "+OK "+banner+" ready\r\n"); err != nil {
		return err
	}
	for i := 0; i < maxCommands; i++ {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		verb, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch strings.ToUpper(verb) {
		case "CAPA":
			err = write(w, "+OK Capability list follows\r\nSTLS\r\n.\r\n")
		case "STLS":
			if err := noPipelinedData(r); err != nil {
				return err
			}
			return write(w, "+OK Begin TLS negotiation\r\n")
		case "QUIT":
			_ = write(w, "+OK Bye\r\n")
			return errClose
		default:
			err = write(w, "-ERR Use STLS first\r\n")
		}
		if err != nil {
			return err
		}
	}
	_ = write(w, "-ERR Too many commands\r\n")
	return errors.New("too many commands before STLS")
}

func (pop3) Upstream(r *bufio.Reader, w io.Writer) error {
	g, err := readLine(r)
	if err != nil || !strings.HasPrefix(g, "+OK") {
		return fmt.Errorf("upstream greeting %q: %v", g, err)
	}
	if err := write(w, "STLS\r\n"); err != nil {
		return err
	}
	l, err := readLine(r)
	if err != nil || !strings.HasPrefix(l, "+OK") {
		return fmt.Errorf("upstream STLS %q: %v", l, err)
	}
	return nil
}
