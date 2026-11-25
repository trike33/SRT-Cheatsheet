package ldap

import (
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldaplib "github.com/go-ldap/ldap/v3"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

// fakeLDAPServer starts a minimal, loopback-only LDAP server that
// understands exactly the two requests Phase 1's probe sends: a simple
// BindRequest (checkBind decides whether it succeeds, given the DN and
// password it was sent) and a base-object SearchRequest, always
// answered as a RootDSE with one canned entry. Anything else
// (Unbind, a protocol error) ends the connection.
func fakeLDAPServer(t *testing.T, checkBind func(dn, password string) bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleLDAPConn(c, checkBind)
		}
	}()
	return ln.Addr().String()
}

func handleLDAPConn(c net.Conn, checkBind func(dn, password string) bool) {
	defer c.Close()
	for {
		pkt, err := ber.ReadPacket(c)
		if err != nil || len(pkt.Children) < 2 {
			return
		}
		msgID, _ := pkt.Children[0].Value.(int64)
		op := pkt.Children[1]

		switch int(op.Tag) {
		case ldaplib.ApplicationBindRequest:
			var dn, password string
			if len(op.Children) >= 2 {
				dn, _ = op.Children[1].Value.(string)
			}
			if len(op.Children) >= 3 {
				password = string(op.Children[2].Data.Bytes())
			}
			code := uint64(0) // success
			if !checkBind(dn, password) {
				code = 49 // invalidCredentials
			}
			writeResult(c, msgID, ldaplib.ApplicationBindResponse, code, "")
		case ldaplib.ApplicationSearchRequest:
			writeSearchEntry(c, msgID)
			writeResult(c, msgID, ldaplib.ApplicationSearchResultDone, 0, "")
		case ldaplib.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

// writeResult sends a response with the common
// {resultCode, matchedDN, errorMessage} shape every non-search LDAP
// response (BindResponse, SearchResultDone, ...) uses.
func writeResult(c net.Conn, msgID int64, application int, resultCode uint64, errMsg string) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(application), nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errMsg, "errorMessage"))
	send(c, msgID, op)
}

// writeSearchEntry sends one canned RootDSE SearchResultEntry.
func writeSearchEntry(c net.Conn, msgID int64) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldaplib.ApplicationSearchResultEntry), nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	attrs.AppendChild(attrValue("dnsHostName", "dc01.corp.local"))
	attrs.AppendChild(attrValue("namingContexts", "DC=corp,DC=local"))
	attrs.AppendChild(attrValue("supportedLDAPVersion", "3"))
	op.AppendChild(attrs)

	send(c, msgID, op)
}

func attrValue(name, value string) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
	vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "val"))
	p.AppendChild(vals)
	return p
}

// send writes envelope's actual BER wire encoding (Packet.Bytes()) --
// NOT ber.WritePacket, which despite its name is a human-readable debug
// dump, not a serializer.
func send(c net.Conn, msgID int64, op *ber.Packet) {
	envelope := ber.NewSequence("LDAPMessage")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	envelope.AppendChild(op)
	c.Write(envelope.Bytes())
}

func target(t *testing.T, addr string) protocols.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	tg, err := protocols.ParseTarget(host+":"+portStr, DefaultPort)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tg
}

func TestProbeAnonymousBind(t *testing.T) {
	addr := fakeLDAPServer(t, func(dn, password string) bool {
		return dn == "" && password == ""
	})
	f := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 3*time.Second)
	if f.Err != "" {
		t.Fatalf("unexpected error: %s", f.Err)
	}
	if f.Kind != KindAnonymousBind {
		t.Fatalf("Kind = %q, want %q (detail=%q)", f.Kind, KindAnonymousBind, f.Detail)
	}
	if f.Severity != protocols.High {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.High)
	}
	if !strings.Contains(f.Detail, "dc01.corp.local") || !strings.Contains(f.Detail, "DC=corp,DC=local") {
		t.Errorf("Detail = %q, want it to mention the RootDSE values", f.Detail)
	}
}

func TestProbeSimpleBindBuildsUPNFromDomain(t *testing.T) {
	addr := fakeLDAPServer(t, func(dn, password string) bool {
		return dn == "alice@CORP" && password == "s3cret"
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "s3cret", Domain: "CORP"}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
	if f.Cred.User != "alice" {
		t.Errorf("Cred.User = %q, want %q", f.Cred.User, "alice")
	}
}

func TestProbeSimpleBindNoDomainUsesBareUser(t *testing.T) {
	addr := fakeLDAPServer(t, func(dn, password string) bool {
		return dn == "cn=admin,dc=example,dc=com" && password == "pw"
	})
	creds := []protocols.Credential{protocols.Anonymous, {User: "cn=admin,dc=example,dc=com", Password: "pw"}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginOK {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginOK, f.Detail, f.Err)
	}
}

func TestProbeEveryBindRejected(t *testing.T) {
	addr := fakeLDAPServer(t, func(dn, password string) bool { return false })
	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "wrong"}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if f.Severity != protocols.Info {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.Info)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	f := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond)
	if f.Err == "" {
		t.Fatalf("expected a connection error, got Finding %+v", f)
	}
}

func TestProbeKerberosSkipped(t *testing.T) {
	// -k alone (no password/hash) has nothing else to try: it should be
	// skipped, not attempted as a simple bind with an empty password,
	// and the target reported as every-attempt-rejected.
	addr := fakeLDAPServer(t, func(dn, password string) bool { return false })
	creds := []protocols.Credential{{User: "alice", Kerberos: true}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (Kerberos-only attempt should be skipped, not sent)", f.Kind, KindLoginFailed)
	}
}

func TestProbeHashBindDoesNotCrash(t *testing.T) {
	// A full NTLM/SASL handshake needs a real NTLM-capable LDAP server to
	// exercise end to end (see docs/ARCHITECTURE.md on preferring
	// t.Skip over mocking a capability the test environment doesn't
	// have); this only checks that bind() reaches NTLMBindWithHash and
	// comes back as an ordinary failed attempt against a server that
	// doesn't support it, never a panic or a hang.
	addr := fakeLDAPServer(t, func(dn, password string) bool { return false })
	creds := []protocols.Credential{{User: "administrator", Hash: "aad3b435b51404eeaad3b435b51404ee"}}
	f := probe(target(t, addr), creds, 3*time.Second)
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
}
