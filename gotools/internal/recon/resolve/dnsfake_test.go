package resolve

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// A minimal, test-only authoritative DNS server answering A/CNAME/MX/NS/TXT
// over real DNS wire format, so resolve's -type lookups are verified
// against actual parsed responses rather than trusted on faith.

type fakeMX struct {
	Pref uint16
	Host string
}

type fakeZone struct {
	a     map[string][]string
	cname map[string]string
	mx    map[string][]fakeMX
	ns    map[string][]string
	txt   map[string][]string
}

func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name == "" {
		return []byte{0}
	}
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0)
}

func parseName(msg []byte, off int) (name string, newOff int) {
	var labels []string
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		off++
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), off
}

func buildDNSResponse(query []byte, zone fakeZone) []byte {
	if len(query) < 12 {
		return nil
	}
	name, off := parseName(query, 12)
	if off+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[off : off+2])
	qclass := binary.BigEndian.Uint16(query[off+2 : off+4])
	questionBytes := query[12 : off+4]
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	var answers [][]byte
	// addAnswerNamed writes a literal (uncompressed) owner name rather than
	// a pointer into the question section: a CNAME chain's trailing A
	// record is owned by the CNAME's target, not the originally queried
	// name, so a fixed pointer to the question wouldn't be correct there.
	addAnswerNamed := func(owner string, rtype uint16, rdata []byte) {
		a := encodeName(owner)
		a = binary.BigEndian.AppendUint16(a, rtype)
		a = binary.BigEndian.AppendUint16(a, qclass)
		a = binary.BigEndian.AppendUint32(a, 300)
		a = binary.BigEndian.AppendUint16(a, uint16(len(rdata)))
		a = append(a, rdata...)
		answers = append(answers, a)
	}
	addAnswer := func(rtype uint16, rdata []byte) { addAnswerNamed(name, rtype, rdata) }

	switch qtype {
	case 1: // A -- real nameservers chase a CNAME chain and return the
		// CNAME record(s) plus the final name's A record(s) in one
		// response; net.Resolver.LookupCNAME relies on exactly this (it
		// has no dedicated CNAME-type query path -- verified against
		// go doc net.Resolver.LookupCNAME, which found this out the hard
		// way on the first version of this fake server).
		if target, ok := zone.cname[name]; ok {
			addAnswerNamed(name, 5, encodeName(target))
			for _, ip := range zone.a[target] {
				addAnswerNamed(target, 1, net.ParseIP(ip).To4())
			}
		} else {
			for _, ip := range zone.a[name] {
				addAnswer(1, net.ParseIP(ip).To4())
			}
		}
	case 2: // NS
		for _, ns := range zone.ns[name] {
			addAnswer(2, encodeName(ns))
		}
	case 5: // CNAME -- only reachable if something ever queries type
		// CNAME directly; kept for completeness/robustness even though
		// LookupCNAME itself doesn't take this path (see case 1 above).
		if target, ok := zone.cname[name]; ok {
			addAnswer(5, encodeName(target))
		}
	case 15: // MX
		for _, mx := range zone.mx[name] {
			var rdata []byte
			rdata = binary.BigEndian.AppendUint16(rdata, mx.Pref)
			rdata = append(rdata, encodeName(mx.Host)...)
			addAnswer(15, rdata)
		}
	case 16: // TXT
		for _, txt := range zone.txt[name] {
			rdata := append([]byte{byte(len(txt))}, []byte(txt)...)
			addAnswer(16, rdata)
		}
	}

	resp := []byte{query[0], query[1]} // ID
	flags := uint16(0x8180)
	if len(answers) == 0 {
		flags = 0x8183 // NXDOMAIN
	}
	resp = binary.BigEndian.AppendUint16(resp, flags)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(answers)))
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = append(resp, questionBytes...)
	for _, a := range answers {
		resp = append(resp, a...)
	}
	return resp
}

// startFakeDNS runs a UDP DNS server for the duration of the test and
// returns a *net.Resolver that only ever talks to it, regardless of what
// host/port Go's resolver thinks it's dialing (tests override resolve.go's
// newResolver var with the result).
func startFakeDNS(t *testing.T, zone fakeZone) *net.Resolver {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := buildDNSResponse(buf[:n], zone)
			if resp != nil {
				conn.WriteToUDP(resp, addr)
			}
		}
	}()
	addr := conn.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func withFakeDNS(t *testing.T, zone fakeZone) {
	t.Helper()
	old := newResolver
	r := startFakeDNS(t, zone)
	newResolver = func() *net.Resolver { return r }
	t.Cleanup(func() { newResolver = old })
}

// Sanity check on the fake server itself, independent of resolve.Run --
// if this fails, a failure in the real tests means the fake server is
// broken, not resolve.go.
func TestFakeDNSServerAnswersDirectly(t *testing.T) {
	r := startFakeDNS(t, fakeZone{
		a:   map[string][]string{"a.test": {"1.2.3.4"}},
		txt: map[string][]string{"txt.test": {"hello"}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "a.test")
	if err != nil || len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Errorf("LookupHost = %v, %v", addrs, err)
	}
	txts, err := r.LookupTXT(ctx, "txt.test")
	if err != nil || len(txts) != 1 || txts[0] != "hello" {
		t.Errorf("LookupTXT = %v, %v", txts, err)
	}
	if _, err := r.LookupHost(ctx, "nxdomain.test"); err == nil {
		t.Error("expected NXDOMAIN to error")
	}
}
