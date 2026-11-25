package ldap

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldaplib "github.com/go-ldap/ldap/v3"

	"github.com/trike33/srt-cheatsheet/gotools/internal/protocols"
)

const testBaseDN = "DC=corp,DC=local"

// fakeConfig configures fakeLDAPServer's canned responses.
type fakeConfig struct {
	checkBind func(dn, password string) bool
	// rootDSE's attributes (defaults to a plausible RootDSE if nil).
	rootDSE map[string][]string
	// users, one map per canned user, for the bulk subtree search.
	users []map[string][]string
	// pwdPolicy's attributes, for the base-object search on testBaseDN
	// (defaults to a non-weak policy if nil).
	pwdPolicy map[string][]string
}

// fakeLDAPServer starts a minimal, loopback-only LDAP server that
// understands exactly what Phase 1/2's probe sends: a simple
// BindRequest (cfg.checkBind decides whether it succeeds, given the DN
// and password it was sent) and three shapes of SearchRequest -- a
// RootDSE read (base "", base-object scope), the password-policy read
// (base testBaseDN, base-object scope) and the bulk user search (base
// testBaseDN, whole-subtree scope) -- each answered from cfg. Anything
// else (Unbind, a protocol error) ends the connection.
func fakeLDAPServer(t *testing.T, cfg fakeConfig) string {
	t.Helper()
	if cfg.rootDSE == nil {
		cfg.rootDSE = map[string][]string{
			"dnsHostName":           {"dc01.corp.local"},
			"namingContexts":        {testBaseDN},
			"defaultNamingContext":  {testBaseDN},
			"supportedLDAPVersion":  {"3"},
		}
	}
	if cfg.pwdPolicy == nil {
		cfg.pwdPolicy = map[string][]string{
			"minPwdLength":     {"14"},
			"lockoutThreshold": {"10"},
			"maxPwdAge":        {"-36288000000000"}, // 42 days
			"pwdProperties":    {"1"},                // complexity required
		}
	}
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
			go handleLDAPConn(c, cfg)
		}
	}()
	return ln.Addr().String()
}

func handleLDAPConn(c net.Conn, cfg fakeConfig) {
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
			if !cfg.checkBind(dn, password) {
				code = 49 // invalidCredentials
			}
			writeResult(c, msgID, ldaplib.ApplicationBindResponse, code, "")
		case ldaplib.ApplicationSearchRequest:
			var baseDN string
			var scope int64
			if len(op.Children) >= 2 {
				baseDN, _ = op.Children[0].Value.(string)
				scope, _ = op.Children[1].Value.(int64)
			}
			switch {
			case baseDN == "" && scope == int64(ldaplib.ScopeBaseObject):
				writeSearchEntry(c, msgID, cfg.rootDSE)
			case baseDN == testBaseDN && scope == int64(ldaplib.ScopeBaseObject):
				writeSearchEntry(c, msgID, cfg.pwdPolicy)
			case baseDN == testBaseDN && scope == int64(ldaplib.ScopeWholeSubtree):
				for _, u := range cfg.users {
					writeSearchEntry(c, msgID, u)
				}
			}
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

// writeSearchEntry sends one SearchResultEntry built from attrs.
func writeSearchEntry(c net.Conn, msgID int64, attrs map[string][]string) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldaplib.ApplicationSearchResultEntry), nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "objectName"))

	attrSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, values := range attrs {
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range values {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		}
		p.AppendChild(vals)
		attrSeq.AppendChild(p)
	}
	op.AppendChild(attrSeq)

	send(c, msgID, op)
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
	addr := fakeLDAPServer(t, fakeConfig{checkBind: func(dn, password string) bool { return dn == "" && password == "" }})
	findings := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 3*time.Second, false)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (enum disabled)", len(findings))
	}
	f := findings[0]
	if f.Err != "" {
		t.Fatalf("unexpected error: %s", f.Err)
	}
	if f.Kind != KindAnonymousBind {
		t.Fatalf("Kind = %q, want %q (detail=%q)", f.Kind, KindAnonymousBind, f.Detail)
	}
	if f.Severity != protocols.High {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.High)
	}
	if !strings.Contains(f.Detail, "dc01.corp.local") || !strings.Contains(f.Detail, testBaseDN) {
		t.Errorf("Detail = %q, want it to mention the RootDSE values", f.Detail)
	}
}

func TestProbeSimpleBindBuildsUPNFromDomain(t *testing.T) {
	addr := fakeLDAPServer(t, fakeConfig{checkBind: func(dn, password string) bool {
		return dn == "alice@CORP" && password == "s3cret"
	}})
	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "s3cret", Domain: "CORP"}}
	findings := probe(target(t, addr), creds, 3*time.Second, false)
	if len(findings) != 1 || findings[0].Kind != KindLoginOK {
		t.Fatalf("findings = %+v, want exactly one login-ok", findings)
	}
	if findings[0].Cred.User != "alice" {
		t.Errorf("Cred.User = %q, want %q", findings[0].Cred.User, "alice")
	}
}

func TestProbeSimpleBindNoDomainUsesBareUser(t *testing.T) {
	addr := fakeLDAPServer(t, fakeConfig{checkBind: func(dn, password string) bool {
		return dn == "cn=admin,dc=example,dc=com" && password == "pw"
	}})
	creds := []protocols.Credential{protocols.Anonymous, {User: "cn=admin,dc=example,dc=com", Password: "pw"}}
	findings := probe(target(t, addr), creds, 3*time.Second, false)
	if len(findings) != 1 || findings[0].Kind != KindLoginOK {
		t.Fatalf("findings = %+v, want exactly one login-ok", findings)
	}
}

func TestProbeEveryBindRejected(t *testing.T) {
	addr := fakeLDAPServer(t, fakeConfig{checkBind: func(dn, password string) bool { return false }})
	creds := []protocols.Credential{protocols.Anonymous, {User: "alice", Password: "wrong"}}
	findings := probe(target(t, addr), creds, 3*time.Second, false)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Kind != KindLoginFailed {
		t.Fatalf("Kind = %q, want %q (detail=%q err=%q)", f.Kind, KindLoginFailed, f.Detail, f.Err)
	}
	if f.Severity != protocols.Info {
		t.Errorf("Severity = %q, want %q", f.Severity, protocols.Info)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 1}
	findings := probe(tg, []protocols.Credential{protocols.Anonymous}, 300*time.Millisecond, false)
	if len(findings) != 1 || findings[0].Err == "" {
		t.Fatalf("expected a single connection-error Finding, got %+v", findings)
	}
}

func TestProbeHashBindDoesNotCrash(t *testing.T) {
	// A full NTLM/SASL handshake needs a real NTLM-capable LDAP server to
	// exercise end to end (see docs/ARCHITECTURE.md on preferring
	// t.Skip over mocking a capability the test environment doesn't
	// have); this only checks that bind() reaches NTLMBindWithHash and
	// comes back as an ordinary failed attempt against a server that
	// doesn't support it, never a panic or a hang.
	addr := fakeLDAPServer(t, fakeConfig{checkBind: func(dn, password string) bool { return false }})
	creds := []protocols.Credential{{User: "administrator", Hash: "aad3b435b51404eeaad3b435b51404ee"}}
	findings := probe(target(t, addr), creds, 3*time.Second, false)
	if len(findings) != 1 || findings[0].Kind != KindLoginFailed {
		t.Fatalf("findings = %+v, want exactly one login-failed", findings)
	}
}

func TestEnumerateOnSuccessfulBind(t *testing.T) {
	addr := fakeLDAPServer(t, fakeConfig{
		checkBind: func(dn, password string) bool { return dn == "" && password == "" },
		users: []map[string][]string{
			{"sAMAccountName": {"alice"}, "userAccountControl": {"512"},
				"memberOf": {"CN=Domain Admins,CN=Users," + testBaseDN}},
			{"sAMAccountName": {"svc-backup"}, "userAccountControl": {"4194816"}}, // 512 | 0x400000
			{"sAMAccountName": {"old-disabled"}, "userAccountControl": {"514"}},  // 512 | 2
		},
	})
	findings := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 3*time.Second, true)

	byKind := map[string][]protocols.Finding{}
	for _, f := range findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}

	if len(byKind[KindDomainUsers]) != 1 {
		t.Fatalf("findings = %+v, want exactly one domain-users finding", findings)
	}
	if !strings.Contains(byKind[KindDomainUsers][0].Detail, "3 user(s)") ||
		!strings.Contains(byKind[KindDomainUsers][0].Detail, "2 enabled") ||
		!strings.Contains(byKind[KindDomainUsers][0].Detail, "1 disabled") {
		t.Errorf("domain-users Detail = %q, want counts 3/2 enabled/1 disabled", byKind[KindDomainUsers][0].Detail)
	}

	if len(byKind[KindASREPRoastable]) != 1 {
		t.Fatalf("findings = %+v, want exactly one asrep-roastable finding", findings)
	}
	if !strings.Contains(byKind[KindASREPRoastable][0].Detail, "svc-backup") {
		t.Errorf("asrep-roastable Detail = %q, want it to name svc-backup", byKind[KindASREPRoastable][0].Detail)
	}
	if byKind[KindASREPRoastable][0].Severity != protocols.High {
		t.Errorf("asrep-roastable Severity = %q, want %q", byKind[KindASREPRoastable][0].Severity, protocols.High)
	}

	if len(byKind[KindPrivilegedMembers]) != 1 {
		t.Fatalf("findings = %+v, want exactly one privileged-group-members finding", findings)
	}
	if !strings.Contains(byKind[KindPrivilegedMembers][0].Detail, "Domain Admins") ||
		!strings.Contains(byKind[KindPrivilegedMembers][0].Detail, "alice") {
		t.Errorf("privileged-group-members Detail = %q, want Domain Admins: alice", byKind[KindPrivilegedMembers][0].Detail)
	}

	if len(byKind[KindPasswordPolicy]) != 1 {
		t.Fatalf("findings = %+v, want exactly one password-policy finding (the default fake policy isn't weak)", findings)
	}
}

func TestEnumerateFlagsWeakPasswordPolicy(t *testing.T) {
	addr := fakeLDAPServer(t, fakeConfig{
		checkBind: func(dn, password string) bool { return dn == "" && password == "" },
		pwdPolicy: map[string][]string{
			"minPwdLength":     {"4"},
			"lockoutThreshold": {"0"},
			"maxPwdAge":        {"0"},
			"pwdProperties":    {"0"},
		},
	})
	findings := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 3*time.Second, true)

	var policy *protocols.Finding
	for i := range findings {
		if findings[i].Kind == KindWeakPasswordPolicy {
			policy = &findings[i]
		}
	}
	if policy == nil {
		t.Fatalf("findings = %+v, want a weak-password-policy finding", findings)
	}
	if policy.Severity != protocols.Medium {
		t.Errorf("Severity = %q, want %q", policy.Severity, protocols.Medium)
	}
	for _, want := range []string{"minLength=4", "complexity=not required", "maxAge=never expires", "lockoutThreshold=0"} {
		if !strings.Contains(policy.Detail, want) {
			t.Errorf("Detail = %q, want it to contain %q", policy.Detail, want)
		}
	}
}

func TestEnumerateDisabledByFlag(t *testing.T) {
	addr := fakeLDAPServer(t, fakeConfig{
		checkBind: func(dn, password string) bool { return dn == "" && password == "" },
		users:     []map[string][]string{{"sAMAccountName": {"alice"}, "userAccountControl": {"512"}}},
	})
	findings := probe(target(t, addr), []protocols.Credential{protocols.Anonymous}, 3*time.Second, false)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the bind finding (enum disabled)", findings)
	}
}

func TestAdInterval100nsToDays(t *testing.T) {
	cases := []struct{ ticks, wantDays int64 }{
		{-36288000000000, 42},
		{36288000000000, 42}, // already positive: still converts correctly
		{0, 0},
		{-864000000000, 1},
	}
	for _, c := range cases {
		if got := adInterval100nsToDays(c.ticks); got != c.wantDays {
			t.Errorf("adInterval100nsToDays(%d) = %d, want %d", c.ticks, got, c.wantDays)
		}
	}
}

func TestJoinCapped(t *testing.T) {
	if got := joinCapped([]string{"a", "b"}, 5); got != "a, b" {
		t.Errorf("joinCapped under cap = %q", got)
	}
	got := joinCapped([]string{"a", "b", "c", "d"}, 2)
	if got != "a, b, +2 more" {
		t.Errorf("joinCapped over cap = %q, want %q", got, "a, b, +2 more")
	}
}

func TestWriteKrb5Conf(t *testing.T) {
	path, cleanup, err := writeKrb5Conf("CORP.LOCAL", "10.0.0.5")
	if err != nil {
		t.Fatalf("writeKrb5Conf: %v", err)
	}
	defer cleanup()
	data, err := readFile(path)
	if err != nil {
		t.Fatalf("reading written conf: %v", err)
	}
	for _, want := range []string{"default_realm = CORP.LOCAL", "CORP.LOCAL = {", "kdc = 10.0.0.5"} {
		if !strings.Contains(data, want) {
			t.Errorf("krb5.conf = %q, want it to contain %q", data, want)
		}
	}
	// cleanup actually removes the temp file.
	cleanup()
	if _, err := readFile(path); err == nil {
		t.Errorf("file %q still exists after cleanup", path)
	}
}

func TestKerberosBindRequiresDomainAndPassword(t *testing.T) {
	tg := protocols.Target{Host: "127.0.0.1", Port: 389}
	if err := kerberosBind(nil, tg, protocols.Credential{User: "alice", Kerberos: true}); err == nil {
		t.Error("kerberosBind with no -d: want error, got nil")
	}
	if err := kerberosBind(nil, tg, protocols.Credential{User: "alice", Domain: "CORP", Kerberos: true}); err == nil {
		t.Error("kerberosBind with no -p (and no -H support): want error, got nil")
	}
}

func TestProbeKerberosBindFailsCleanly(t *testing.T) {
	// A real GSSAPI/AS-REQ exchange needs a live KDC to verify end to
	// end (see kerberosBind's doc comment and docs/ROADMAP.md); this
	// only checks that -k reaches gokrb5 and comes back as an ordinary
	// failed attempt -- never a panic or a hang -- when nothing is
	// listening on the target's port 88.
	addr := fakeLDAPServer(t, fakeConfig{checkBind: func(dn, password string) bool { return false }})
	creds := []protocols.Credential{{User: "alice", Password: "pw", Domain: "CORP.LOCAL", Kerberos: true}}
	// kerberosBind dials the KDC at the target's HOST on port 88
	// regardless of the LDAP port in tg -- nothing listens there, so
	// this exercises the real gokrb5 dial-and-fail path without ever
	// touching the fake LDAP server's own port.
	findings := probe(target(t, addr), creds, 2*time.Second, false)
	if len(findings) != 1 || findings[0].Kind != KindLoginFailed {
		t.Fatalf("findings = %+v, want exactly one login-failed (no KDC listening on port 88)", findings)
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
