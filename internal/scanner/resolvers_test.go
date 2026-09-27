package scanner

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
)

// A resolver that answers for a name that cannot exist is dropped; one that
// says "no such host" is kept. Both are served here, so the test needs no
// network.
func TestCheckResolversDropsLiars(t *testing.T) {
	honest := serveDNS(t, false)
	liar := serveDNS(t, true)
	good, dropped := checkResolvers(context.Background(), []string{honest, liar}, 4)
	if len(good) != 1 || good[0] != honest {
		t.Errorf("kept %v, want only the honest resolver %s", good, honest)
	}
	if dropped != 1 {
		t.Errorf("dropped %d, want 1", dropped)
	}
}

// A list with a liar in it is rewritten without it; a list that is all good
// is left alone, so the caller keeps the file it already had.
func TestVettedResolvers(t *testing.T) {
	honest := serveDNS(t, false)
	liar := serveDNS(t, true)
	write := func(lines ...string) string {
		f, err := os.CreateTemp(t.TempDir(), "r-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(strings.Join(lines, "\n") + "\n")
		_ = f.Close()
		return f.Name()
	}
	out, kept, dropped, err := vettedResolvers(context.Background(), write(honest, liar), 4)
	if err != nil {
		t.Fatal(err)
	}
	if out == "" || kept != 1 || dropped != 1 {
		t.Fatalf("out=%q kept=%d dropped=%d", out, kept, dropped)
	}
	defer os.Remove(out)
	body, _ := os.ReadFile(out)
	if strings.TrimSpace(string(body)) != honest {
		t.Errorf("wrote %q, want just %s", body, honest)
	}

	if out, _, dropped, err := vettedResolvers(context.Background(), write(honest), 4); err != nil ||
		out != "" || dropped != 0 {
		t.Errorf("a clean list should be left alone: out=%q dropped=%d err=%v", out, dropped, err)
	}
}

// serveDNS runs a tiny UDP responder: it either answers every A query with
// 127.0.0.1 (a liar) or with NXDOMAIN (honest). It returns its address.
func serveDNS(t *testing.T, lie bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(dnsReply(buf[:n], lie), addr)
		}
	}()
	return pc.LocalAddr().String()
}

// dnsReply builds an answer to a query: the question echoed back, and either
// one A record or the "name does not exist" code.
func dnsReply(q []byte, lie bool) []byte {
	if len(q) < 12 {
		return nil
	}
	r := make([]byte, len(q))
	copy(r, q)
	r[2] = 0x81 // response, recursion desired
	r[3] = 0x80 // recursion available, rcode 0
	if !lie {
		r[3] |= 3 // NXDOMAIN
	}
	// question count stays 1; answer count is 1 only when we invent one.
	r[6], r[7] = 0, 0
	if !lie {
		return r
	}
	// Walk the question's name to find where the record can be appended.
	i := 12
	for i < len(r) && r[i] != 0 {
		i += int(r[i]) + 1
	}
	i += 5 // the zero label, then type and class
	if i > len(r) {
		return r
	}
	r[6], r[7] = 0, 1
	ans := []byte{
		0xc0, 0x0c, // the name, pointing back at the question
		0, 1, 0, 1, // type A, class IN
		0, 0, 0, 60, // time to live
		0, 4, 127, 0, 0, 1, // four bytes: 127.0.0.1
	}
	return append(r[:i], ans...)
}
