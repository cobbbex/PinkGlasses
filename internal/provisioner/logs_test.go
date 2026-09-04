package provisioner

import "testing"

func TestDemuxDockerLog(t *testing.T) {
	// Two framed lines on stderr (stream 2), as docker sends them.
	frame := func(stream byte, s string) []byte {
		n := len(s)
		return append([]byte{stream, 0, 0, 0,
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, s...)
	}
	raw := append(frame(1, "starting\n"), frame(2, "wg: Unable to access interface\n")...)
	if got, want := demuxDockerLog(raw), "starting\nwg: Unable to access interface\n"; got != want {
		t.Errorf("framed: got %q want %q", got, want)
	}
	// An unframed (TTY) log comes back as it is rather than as gibberish.
	plain := []byte("plain line one\nplain line two\n")
	if got := demuxDockerLog(plain); got != string(plain) {
		t.Errorf("unframed: got %q", got)
	}
	// A truncated frame must not panic or drop everything.
	trunc := frame(2, "cut off here")[:12]
	if got := demuxDockerLog(trunc); got == "" {
		t.Errorf("truncated frame lost all output")
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("", "none"); got != "none" {
		t.Errorf("empty: %q", got)
	}
	// The last lines are kept: tools say what went wrong at the end.
	got := firstLine("a\nb\nc\nd\ne", "none")
	if got != "c | d | e" {
		t.Errorf("tail: %q", got)
	}
}
