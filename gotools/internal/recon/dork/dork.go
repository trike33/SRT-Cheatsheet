package dork

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/cli"
	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
	"github.com/trike33/srt-cheatsheet/gotools/internal/netx"
	"github.com/trike33/srt-cheatsheet/gotools/internal/store"
)

func init() {
	cli.Register(&cli.Command{
		Name:    "dork",
		Group:   "WEB recon",
		Summary: "Google dorking: generate (and, with a Custom Search API key, run) advanced search-operator queries",
		Run:     Run,
	})
}

// EnvAPIKey/EnvCX are the environment variables -search falls back to when
// -api-key/-cx aren't given, so a key doesn't have to be typed (and logged
// in shell history) on every invocation.
const (
	EnvAPIKey = "SRT_GOOGLE_API_KEY"
	EnvCX     = "SRT_GOOGLE_CSE_ID"
)

func Run(args []string) error {
	fs := flag.NewFlagSet("dork", flag.ExitOnError)
	fs.Usage = func() {
		cli.PrintGroupedUsage(fs, []cli.UsageSection{
			{Title: "INPUT", Names: []string{"d", "l", "from", "where", "name", "categories", "list-categories"}},
			{Title: "SEARCH (Google Custom Search API)", Names: []string{"search", "api-key", "cx", "num", "delay", "max-daily"}},
			{Title: "OUTPUT", Names: []string{"o", "json"}},
		})
	}
	domain := fs.String("d", "", "single target domain")
	list := fs.String("l", "", "file of target domains, one per line (or stdin, else the project db's domain records -- see -from)")
	fb := store.BindInputFallback(fs, "dork", "domain")
	name := fs.String("name", "", "engagement/org name, for name-scoped categories (paste sites, cloud buckets, source hosting -- see -list-categories)")
	categoriesFlag := fs.String("categories", "", "comma list of categories to generate (default: every category the given -d/-l and/or -name support; see -list-categories)")
	listCategories := fs.Bool("list-categories", false, "print every category name and description, then exit")
	doSearch := fs.Bool("search", false, "actually run each query against the Google Custom Search JSON API (needs -api-key/-cx or "+EnvAPIKey+"/"+EnvCX+"); without this, only the queries/search URLs are printed -- no network traffic at all")
	apiKey := fs.String("api-key", "", "Google Custom Search API key (default: "+EnvAPIKey+")")
	cx := fs.String("cx", "", "Google Programmable Search Engine ID (default: "+EnvCX+")")
	num := fs.Int("num", 10, "results per query to request (max 10 -- the API's own per-request limit)")
	delay := fs.Duration("delay", 1*time.Second, "with -search: delay between queries, to stay well under the free tier's daily quota")
	maxDaily := fs.Int("max-daily", DefaultMaxDaily, fmt.Sprintf("with -search: hard cap on queries sent per API key per UTC day, tracked in %s across every srt dork/pipeline run -- defaults to the Custom Search API's free-tier limit (%d) so a default run can never bill anything; raise it only if you've deliberately enabled billing on that key", quotaFile, dailyFreeQuota))
	out := fs.String("o", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of plain text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *listCategories {
		for _, c := range categories {
			scope := "domain"
			if c.NeedsName {
				scope = "name"
			}
			fmt.Printf("%-13s (%s) %s\n", c.Name, scope, c.Description)
		}
		return nil
	}

	var domains []string
	if *domain != "" {
		domains = append(domains, *domain)
	}
	if *list != "" || fs.NArg() > 0 || *domain == "" {
		if lines, _, err := fb.Resolve(*list, fs.Args()); err == nil {
			domains = append(domains, lines...)
		} else if *domain == "" {
			return err
		}
	}
	domains = ioutil.DedupStrings(domains)
	if len(domains) == 0 && *name == "" {
		return ioutil.ErrMissing("no target: pass -d <domain>, -l <file>, and/or -name <org name>")
	}

	var categoryWant []string
	if *categoriesFlag != "" {
		for _, c := range strings.Split(*categoriesFlag, ",") {
			if c = strings.TrimSpace(c); c != "" {
				categoryWant = append(categoryWant, c)
			}
		}
	}

	var queries []Query
	if len(domains) == 0 {
		queries = Generate("", *name, categoryWant)
	} else {
		for _, d := range domains {
			queries = append(queries, Generate(d, *name, categoryWant)...)
		}
	}
	if len(queries) == 0 {
		return ioutil.ErrMissing("no categories matched -d/-l/-name and -categories; see -list-categories")
	}

	w, err := ioutil.Output(*out)
	if err != nil {
		return err
	}
	defer w.Close()

	if !*doSearch {
		for _, q := range queries {
			if *jsonOut {
				b, _ := json.Marshal(map[string]string{"category": q.Category, "query": q.Query, "url": SearchURL(q.Query)})
				fmt.Fprintln(w, string(b))
			} else {
				fmt.Fprintf(w, "[%s] %s\n", q.Category, SearchURL(q.Query))
			}
		}
		return nil
	}

	key := *apiKey
	if key == "" {
		key = os.Getenv(EnvAPIKey)
	}
	cxID := *cx
	if cxID == "" {
		cxID = os.Getenv(EnvCX)
	}
	if key == "" || cxID == "" {
		return ioutil.ErrMissing("-search needs -api-key/-cx or " + EnvAPIKey + "/" + EnvCX + " set (https://developers.google.com/custom-search/v1/overview for how to get both)")
	}

	if *maxDaily <= 0 {
		return ioutil.ErrMissing("-max-daily must be at least 1")
	}

	client := netx.NewClient(15*time.Second, false)
	var totalHits, sent int
	sink := store.CurrentSink()
	for i, q := range queries {
		if i > 0 && *delay > 0 {
			time.Sleep(*delay)
		}

		used, allowed, qerr := reserveQuota(key, *maxDaily)
		if qerr != nil {
			return fmt.Errorf("dork: daily-quota tracking: %w", qerr)
		}
		if !allowed {
			ioutil.Warn("dork: daily quota reached (%d/%d queries already sent today for this API key) -- stopping before \"%s\" and %d more quer(ies) to avoid billing; raise -max-daily only if you've deliberately enabled billing on this key, or wait for the next UTC day", used, *maxDaily, q.Query, len(queries)-i)
			break
		}
		if used == *maxDaily {
			ioutil.Warn("dork: this is query %d/%d for today's quota -- no more will be sent after it unless -max-daily is raised", used, *maxDaily)
		}

		hits, err := search(client, key, cxID, q.Query, *num)
		sent++
		if err != nil {
			ioutil.Warn("[%s] %v", q.Category, err)
			continue
		}
		ioutil.Warn("[%s] %d hit(s): %s", q.Category, len(hits), q.Query)
		for _, h := range hits {
			h.Category, h.Query = q.Category, q.Query
			totalHits++
			sink.Add(store.TextRecord("dork", h.URL))
			if *jsonOut {
				b, _ := json.Marshal(h)
				fmt.Fprintln(w, string(b))
			} else {
				fmt.Fprintln(w, h.URL)
			}
		}
	}
	ioutil.Warn("dork: %d/%d planned quer(ies) sent, %d hit(s) total", sent, len(queries), totalHits)
	return nil
}
