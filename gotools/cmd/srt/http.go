package main

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

const defaultUA = "srt-recon/1.0 (+bug-bounty)"

// newHTTPClient builds an HTTP client for recon use. insecure skips TLS
// verification (the Python scripts all ran with verify=False, since target
// certs are routinely broken), and timeout bounds each request.
func newHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	return newHTTPClientOpts(timeout, insecure, "", true)
}

// newHTTPClientOpts is the fully-configurable constructor. proxyURL overrides
// the environment proxy when set (e.g. http://127.0.0.1:8080 to route through
// Burp); followRedirects=false returns the 3xx response itself untouched, which
// a fuzzer wants so it can see and reason about redirects.
func newHTTPClientOpts(timeout time.Duration, insecure bool, proxyURL string, followRedirects bool) *http.Client {
	proxy := http.ProxyFromEnvironment
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			proxy = http.ProxyURL(u)
		} else {
			warn("ignoring invalid -proxy %q: %v", proxyURL, err)
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

// getBody issues a GET with our default User-Agent and returns the response.
// The caller is responsible for closing resp.Body.
func httpGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUA)
	return client.Do(req)
}
