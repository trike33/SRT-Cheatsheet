package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

const defaultUA = "srt-recon/1.0 (+bug-bounty)"

// newHTTPClient builds an HTTP client for recon use. insecure skips TLS
// verification (the Python scripts all ran with verify=False, since target
// certs are routinely broken), and timeout bounds each request.
func newHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyFromEnvironment, // respect HTTP(S)_PROXY
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
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
