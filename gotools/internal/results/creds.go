package results

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/colorout"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "creds",
		Group:   "results",
		Summary: "List every accepted login/session a protocol client saved (ftp/telnet/smb/ldap/ssh/mssql/vnc/rdp)",
		Run:     RunCreds,
	})
}

// RunCreds queries the results database for exactly the Findings each
// protocol-client package marked Accepted (internal/protocols.Finding's
// own field, stored as Data["ok"] -- see its doc comment on why that's a
// more reliable signal than guessing from Kind/Severity alone) -- a
// focused "what got in" report, pulled out of `results`' own
// everything-including-banners-and-rejections view rather than
// duplicating its query logic.
func RunCreds(args []string) error {
	fs := flag.NewFlagSet("creds", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "FILTERS", Names: []string{"kind", "host", "run", "history"}},
			{Title: "OUTPUT", Names: []string{"limit", "json", "keys", "count", "color"}},
		})
	}
	var f queryFilter
	kindFlag := fs.String("kind", "", "comma list, narrowing within ftp,telnet,smb,ldap,ssh,mssql,vnc,rdp (default: all of them)")
	fs.StringVar(&f.host, "host", "", "host substring")
	fs.Int64Var(&f.run, "run", 0, "only this run id (default: newest observation of every result across all runs)")
	fs.BoolVar(&f.history, "history", false, "every observation from every run, not just the newest")
	limit := fs.Int("limit", 0, "max rows (0 = all)")
	jsonOut := fs.Bool("json", false, "JSON lines")
	keysOut := fs.Bool("keys", false, "print only \"host:port\", one per line -- pipe-friendly into another command's -l")
	count := fs.Bool("count", false, "print the number of matching creds")
	colorFlag := fs.String("color", "auto", "color the table output: auto|always|never (ignored with -json/-keys/-count)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cm := colorout.ParseMode(*colorFlag)

	if *kindFlag != "" {
		for _, k := range strings.Split(*kindFlag, ",") {
			if k = strings.TrimSpace(k); k == "" {
				continue
			}
			if !protocolKinds[k] {
				return fmt.Errorf("creds: -kind %q is not a protocol-client kind (ftp, telnet, smb, ldap, ssh, mssql, vnc, rdp)", k)
			}
			f.kinds = append(f.kinds, k)
		}
	} else {
		for k := range protocolKinds {
			f.kinds = append(f.kinds, k)
		}
	}

	db, err := store.OpenReadable()
	if err != nil {
		return err
	}
	defer db.Close()
	// f.limit is deliberately left unset: the SQL LIMIT it would apply
	// runs before the Data["ok"] filter below, which would cut rows that
	// never had a chance to be a credential at all. -limit is applied to
	// the filtered result instead, further down.
	recs, err := f.query(db)
	if err != nil {
		return err
	}

	creds := filterAccepted(recs)
	if *limit > 0 && len(creds) > *limit {
		creds = creds[:*limit]
	}

	switch {
	case *count:
		fmt.Println(len(creds))
	case *keysOut:
		for _, r := range creds {
			fmt.Println(credTarget(r))
		}
	case *jsonOut:
		for _, r := range creds {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
	default:
		printCredsTable(os.Stdout, creds, cm)
		summary := fmt.Sprintf("%d accepted login(s)/session(s)", len(creds))
		if len(creds) == 0 {
			summary = cm.Wrap(colorout.Yellow, summary)
		} else {
			summary = cm.Wrap(colorout.Green, summary)
		}
		fmt.Fprintln(os.Stderr, summary)
	}
	return nil
}

// filterAccepted narrows recs to exactly the ones internal/protocols'
// Finding.Accepted marked -- a stored record's own Data["ok"] == true --
// what every RunCreds output mode (table, -json, -keys, -count) is
// built from.
func filterAccepted(recs []store.Record) []store.Record {
	var out []store.Record
	for _, r := range recs {
		if ok, _ := r.Data["ok"].(bool); ok {
			out = append(out, r)
		}
	}
	return out
}

// credTarget renders r's target as "host:port" (or just "host" when no
// port was recorded), the same shape every protocol client's own -l
// expects back -- the point of -keys here.
func credTarget(r store.Record) string {
	if r.Port > 0 {
		return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	}
	return r.Host
}

// printCredsTable renders creds as a column-aligned, optionally
// colorized table focused on what a credential/access report needs, not
// every field `results`' own table shows: PROTO, the target, its
// hostname (falling back to the bare host when the protocol never
// captured one -- see protocols.Finding.Hostname's own doc comment),
// the credential that got in ("(anonymous)" when there wasn't one --
// protocols.Credential.String()'s own word, never the password or hash
// itself, same as everywhere else a stored record is read back), and
// the finding's own detail. CRED and DETAIL are colored by severity
// (colorout.SeverityColor), the same scale `results`' own INFO column
// uses for these kinds.
func printCredsTable(w io.Writer, creds []store.Record, cm colorout.Mode) {
	type row struct {
		proto, target, hostname, cred, severity, detail string
	}
	rows := make([]row, len(creds))
	for i, r := range creds {
		hostname, _ := r.Data["hostname"].(string)
		if hostname == "" {
			hostname = r.Host
		}
		cred, _ := r.Data["cred"].(string)
		if cred == "" {
			cred = "(anonymous)"
		}
		severity, _ := r.Data["severity"].(string)
		detail, _ := r.Data["detail"].(string)
		rows[i] = row{proto: strings.ToUpper(r.Kind), target: credTarget(r), hostname: hostname, cred: cred, severity: severity, detail: detail}
	}

	headers := []string{"PROTO", "TARGET", "HOSTNAME", "CRED"}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len([]rune(h))
	}
	for _, r := range rows {
		cells := []string{r.proto, r.target, r.hostname, r.cred}
		for i, c := range cells {
			if n := len([]rune(c)); n > widths[i] {
				widths[i] = n
			}
		}
	}

	fmt.Fprintln(w, strings.Join([]string{
		pad(headers[0], widths[0]), pad(headers[1], widths[1]), pad(headers[2], widths[2]), pad(headers[3], widths[3]), "DETAIL",
	}, "  "))
	for _, r := range rows {
		color := colorout.SeverityColor(r.severity)
		fmt.Fprintln(w, strings.Join([]string{
			cm.PadWrap(colorout.PaletteColor(r.proto), pad(r.proto, widths[0]), widths[0]),
			cm.PadWrap("", pad(r.target, widths[1]), widths[1]),
			cm.PadWrap("", pad(r.hostname, widths[2]), widths[2]),
			cm.PadWrap(color, pad(r.cred, widths[3]), widths[3]),
			cm.Wrap(color, r.detail),
		}, "  "))
	}
}
