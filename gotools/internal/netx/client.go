package netx

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
)

// DefaultUA is the User-Agent every srt HTTP request identifies itself with.
const DefaultUA = "srt-recon/1.0 (+bug-bounty)"

// NewClient builds an HTTP client for recon use. insecure skips TLS
// verification (the Python scripts all ran with verify=False, since target
// certs are routinely broken), and timeout bounds each request.
func NewClient(timeout time.Duration, insecure bool) *http.Client {
	return NewClientOpts(timeout, insecure, "", true)
}

// NewClientOpts is the fully-configurable constructor. proxyURL overrides
// the environment proxy when set (e.g. http://127.0.0.1:8080 to route through
// Burp); followRedirects=false returns the 3xx response itself untouched,
// which a fuzzer wants so it can see and reason about redirects. Every
// client built here has its traffic metered and rate-gated (see traffic.go)
// -- that's the whole reason HTTP client construction lives next to traffic
// accounting instead of standing alone.
func NewClientOpts(timeout time.Duration, insecure bool, proxyURL string, followRedirects bool) *http.Client {
	proxy := http.ProxyFromEnvironment
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			proxy = http.ProxyURL(u)
		} else {
			ioutil.Warn("ignoring invalid -proxy %q: %v", proxyURL, err)
		}
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		DialContext:         countingDialContext,
		ForceAttemptHTTP2:   true,
		Proxy:               proxy,
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
	}
	c := &http.Client{
		Timeout:   timeout,
		Transport: countingTransport{next: tr},
	}
	if !followRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// Get issues a GET with srt's default User-Agent and returns the response.
// The caller is responsible for closing resp.Body.
func Get(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", DefaultUA)
	return client.Do(req)
}
