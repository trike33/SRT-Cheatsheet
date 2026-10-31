// Package payloads holds the vulnerable-parameter wordlists and sensitive
// file extensions, lifted verbatim from WEB/gau_recon.py, that the gau
// subcommands (params, sensitive) classify URLs against -- so the Go tools
// match the original Python exactly.
package payloads

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
