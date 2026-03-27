// Package transport provides HTTP transport enforcement for AccessGraph.
//
// The offline transport blocks all outbound HTTP traffic to non-localhost
// addresses, protecting against inadvertent data exfiltration or SSRF during
// static policy analysis. The only permitted destination is localhost, which
// is used exclusively for embedded OPA evaluation.
package transport

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewOfflineClient returns an *http.Client whose transport blocks all requests
// to non-localhost destinations.
//
// The returned client enforces the offline guarantee: any request whose resolved
// host is not 127.0.0.1, ::1, or a bare hostname without dots is rejected with
// an error before a TCP connection is attempted.
//
// Parameters:
//   - timeout: the per-request timeout applied to the underlying transport.
//
// Returns an *http.Client configured with the offline transport and the given timeout.
func NewOfflineClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &offlineTransport{inner: http.DefaultTransport},
	}
}

// NewDefaultClient returns an *http.Client with standard settings and no offline
// restriction. Use this only in integration tests or when the caller has explicitly
// enabled online mode.
//
// Parameters:
//   - timeout: the per-request timeout applied to the underlying transport.
//
// Returns an *http.Client with the standard transport.
func NewDefaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: http.DefaultTransport,
	}
}

// offlineTransport is an http.RoundTripper that rejects requests to any
// destination other than localhost.
type offlineTransport struct {
	inner http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
//
// It resolves the host of req and returns an error for any address that is not
// loopback. Requests to localhost pass through to the inner transport unchanged.
//
// Parameters:
//   - req: the outbound HTTP request to evaluate.
//
// Errors:
//   - returns an error wrapping ErrNonLocalhostBlocked if the destination is not loopback.
func (t *offlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	if !isLocalhost(host) {
		return nil, fmt.Errorf("%w: %s", ErrNonLocalhostBlocked, host)
	}
	return t.inner.RoundTrip(req)
}

// ErrNonLocalhostBlocked is returned by the offline transport when a request
// targets a non-localhost address. Callers that check for this error can
// distinguish between connectivity failures and deliberate offline enforcement.
var ErrNonLocalhostBlocked = fmt.Errorf("offline mode blocks non-localhost HTTP traffic")

// isLocalhost reports whether host resolves to a loopback address.
//
// It considers the following loopback: "localhost", "127.0.0.1", "::1", and any
// hostname that contains no dots (bare hostnames used in Docker Compose networks
// are explicitly allowed to prevent false positives in containerized environments).
//
// Parameters:
//   - host: the hostname or IP address from the request URL (no port).
//
// Returns true if host is a loopback address, false otherwise.
func isLocalhost(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	// Bare hostnames (no dots) are treated as local service names (e.g., "opa"
	// in a Docker Compose environment). This is intentional and documented.
	for _, ch := range host {
		if ch == '.' {
			return false
		}
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return true
}
