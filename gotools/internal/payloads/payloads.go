// Package payloads holds the vulnerable-parameter wordlists and sensitive
// file extensions, lifted verbatim from WEB/gau_recon.py, that the gau
// subcommands (params, sensitive) classify URLs against -- so the Go tools
// match the original Python exactly. It also holds SecretPatterns, the
// content-based secret/credential signatures `sensitive -content` scans a
// fetched body against -- the methodology gap extension-only filtering
// can't close (see docs/ROADMAP.md).
package payloads

import "regexp"

// Categories maps a vuln class to the parameter markers that hint at it.
// Order matters only for display; lookups scan every category.
var Categories = []struct {
	Name    string
	Markers []string
}{
	{"open-redirect", []string{
		"?next=", "?url=", "?target=", "?rurl=", "?dest=", "?destination=",
		"?redir=", "?redirect_uri=", "?redirect_url=", "?redirect=", "/redirect/",
		"/cgi-bin/redirect.cgi?", "/out/", "/out?", "?view=", "/login?to=",
		"?image_url=", "?go=", "?return=", "?returnTo=", "?return_to=",
		"?checkout_url=", "?continue=", "?return_path=",
	}},
	{"sqli", []string{
		"?id=", "?page=", "?dir=", "?search=", "?category=", "?file=", "?class=",
		"?url=", "?news=", "?item=", "?menu=", "?lang=", "?name=", "?ref=",
		"?title=", "?view=", "?topic=", "?thread=", "?type=", "?date=", "?form=",
		"?join=", "?main=", "?nav=", "?region=",
	}},
	{"xss", []string{
		"?q=", "?s=", "?search=", "?id=", "?lang=", "?keyword=", "?query=",
		"?page=", "?keywords=", "?year=", "?view=", "?email=", "?type=", "?name=",
		"?p=", "?month=", "?image=", "?list_type=", "?url=", "?terms=",
		"?categoryid=", "?key=", "?login=", "?begindate=", "?enddate=",
	}},
	{"lfi", []string{
		"?cat=", "?dir=", "?action=", "?board=", "?date=", "?detail=", "?file=",
		"?download=", "?path=", "?folder=", "?prefix=", "?include=", "?page=",
		"?inc=", "?locate=", "?show=", "?doc=", "?site=", "?type=", "?view=",
		"?content=", "?document=", "?layout=", "?mod=", "?conf=",
	}},
	{"rce", []string{
		"?cmd=", "?exec=", "?command=", "?execute=", "?ping=", "?query=", "?jump=",
		"?code=", "?reg=", "?do=", "?func=", "?arg=", "?option=", "?load=",
		"?process=", "?step=", "?read=", "?function=", "?req=", "?feature=",
		"?exe=", "?module=", "?payload=", "?run=", "?print=",
	}},
	{"ssrf", []string{
		"?dest=", "?redirect=", "?uri=", "?path=", "?continue=", "?url=",
		"?window=", "?next=", "?data=", "?reference=", "?site=", "?html=",
		"?val=", "?validate=", "?domain=", "?callback=", "?return=", "?page=",
		"?feed=", "?host=", "?port=", "?to=", "?out=", "?view=", "?dir=",
	}},
}

// sensitiveExtensions are file extensions worth flagging in crawled/archived URLs.
var SensitiveExtensions = []string{
	".xls", ".xml", ".xlsx", ".json", ".pdf", ".sql", ".doc", ".docx", ".pptx",
	".txt", ".zip", ".tar.gz", ".tgz", ".bak", ".7z", ".rar", ".log", ".cache",
	".secret", ".db", ".backup", ".yml", ".gz", ".config", ".csv", ".yaml",
	".md", ".md5", ".tar", ".xz", ".7zip", ".p12", ".pem", ".key", ".crt",
	".csr", ".sh", ".pl", ".py", ".java", ".class", ".jar", ".war", ".ear",
	".sqlitedb", ".sqlite3", ".dbf", ".db3", ".accdb", ".mdb", ".sqlcipher",
	".gitignore", ".env", ".ini", ".conf", ".properties", ".plist", ".cfg",
}

// SecretPattern is one named, compiled signature SecretPatterns scans a
// fetched body against.
type SecretPattern struct {
	Name string
	Re   *regexp.Regexp
}

// SecretPatterns are the content-based secret/credential signatures
// `sensitive -content` checks a fetched response body against -- a
// deliberately small, high-precision set (specific token prefixes, key
// headers, assignment shapes) over a broad "anything that looks random"
// heuristic, to keep false positives low on arbitrary crawled text.
var SecretPatterns = []SecretPattern{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*['"]?\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{20,}`)},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)},
	{"Stripe Live Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{20,}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----`)},
	{"JSON Web Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Basic Auth in URL", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]{2,10}://[^/\s:@'"]{3,40}:[^/\s:@'"]{3,40}@[^/\s'"]+`)},
	{"Database Connection String", regexp.MustCompile(`(?i)(mongodb(\+srv)?|mysql|postgres(ql)?|redis)://[^:\s'"]+:[^@\s'"]+@[^/\s'"]+`)},
	// The two generic patterns wrap their trigger word in [\w-]* on both
	// sides and make the value's quoting optional, so a key name is matched
	// wherever the word appears inside it -- camelCase ("secretKey",
	// "clientSecret"), snake_case ("secret_key", "my_api_key"), a quoted
	// JSON key ("secretKey": "..."), or an unquoted .env-style assignment
	// (SECRET_KEY=...) -- not only the exact bare word immediately before
	// "=" or ":" that the original, stricter patterns required.
	{"Generic API Key", regexp.MustCompile(`(?i)['"]?[\w-]*(?:api[_-]?key|apikey)[\w-]*['"]?\s*[=:]\s*['"]?[0-9a-zA-Z\-_]{12,64}['"]?`)},
	{"Generic Secret/Password", regexp.MustCompile(`(?i)['"]?[\w-]*(?:secret|passwd|password|token)[\w-]*['"]?\s*[=:]\s*['"]?[^\s'",;]{6,128}['"]?`)},
}
