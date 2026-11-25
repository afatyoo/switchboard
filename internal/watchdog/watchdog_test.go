package watchdog

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"testing"
)

type fakeFW struct{ rules map[int]bool }

func (f *fakeFW) Has(p Port) (bool, error) { return f.rules[p.Public], nil }
func (f *fakeFW) Add(p Port) error         { f.rules[p.Public] = true; return nil }
func (f *fakeFW) Remove(p Port) error      { delete(f.rules, p.Public); return nil }

func TestFailOpenAndRecover(t *testing.T) {
	healthy := map[int]bool{993: true, 587: true}
	fw := &fakeFW{rules: map[int]bool{993: true, 587: true}}
	w := &Watchdog{
		Ports:    []Port{{Public: 993, Local: 10993}, {Public: 587, Local: 10587}},
		Firewall: fw,
		Probe: func(_ context.Context, p Port) error {
			if healthy[p.Public] {
				return nil
			}
			return errors.New("down")
		},
		FailAfter: 3, RecoverAfter: 2,
		Log: log.New(io.Discard, "", 0),
	}
	ctx := context.Background()

	healthy[993] = false
	w.Tick(ctx)
	w.Tick(ctx)
	if !fw.rules[993] {
		t.Fatal("redirect removed before FailAfter")
	}
	w.Tick(ctx)
	if fw.rules[993] {
		t.Fatal("redirect not removed after FailAfter")
	}
	if !fw.rules[587] {
		t.Fatal("healthy port touched")
	}

	healthy[993] = true
	w.Tick(ctx)
	if fw.rules[993] {
		t.Fatal("redirect restored before RecoverAfter")
	}
	w.Tick(ctx)
	if !fw.rules[993] {
		t.Fatal("redirect not restored")
	}
}

func TestFlappingDoesNotRemove(t *testing.T) {
	fw := &fakeFW{rules: map[int]bool{993: true}}
	n := 0
	w := &Watchdog{
		Ports:    []Port{{Public: 993, Local: 10993}},
		Firewall: fw,
		Probe: func(context.Context, Port) error {
			n++
			if n%2 == 0 {
				return nil
			}
			return errors.New("blip")
		},
		FailAfter: 3, RecoverAfter: 3, Log: log.New(io.Discard, "", 0),
	}
	for i := 0; i < 10; i++ {
		w.Tick(context.Background())
	}
	if !fw.rules[993] {
		t.Fatal("single failures removed the redirect")
	}
}

func TestDefaultProbeBanner(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	greeting := "220 ready\r\n"
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewWriter(c).WriteString(greeting)
			io.WriteString(c, greeting)
			c.Close()
		}
	}()
	port, _ := strconv.Atoi(ln.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):])
	if err := probeGreeting(context.Background(), Port{Local: port, Check: "banner"}); err != nil {
		t.Fatal(err)
	}
	if err := probeGreeting(context.Background(), Port{Local: 1, Check: "banner"}); err == nil {
		t.Fatal("closed port reported healthy")
	}
}
