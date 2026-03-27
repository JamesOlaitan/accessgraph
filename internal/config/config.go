// Package config provides configuration loading for AccessGraph.
//
// Configuration is read from environment variables with typed defaults. No
// configuration file is required; the tool is operable from a clean clone
// with only Go installed.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all runtime configuration for AccessGraph.
//
// Fields:
//   - DBPath: path to the SQLite database file; defaults to "accessgraph.db".
//   - PolicyDir: directory containing OPA Rego rules; defaults to "policy".
//   - MaxHops: maximum BFS depth for attack path detection; defaults to 8.
//   - Offline: when true, the HTTP transport rejects all non-localhost outbound
//     connections. Scope is limited to HTTP/HTTPS calls only (e.g. OPA bundle
//     fetches if an external bundle server is configured). It does NOT restrict
//     SQLite file I/O, local filesystem access, or the exec-based tool
//     invocations used by the benchmark runner. Defaults to true so the tool is
//     air-gap safe out of the box; set ACCESSGRAPH_OFFLINE=false only when an
//     external OPA bundle server or remote AWS endpoint is required.
//   - RequestTimeout: HTTP timeout for any external calls (OPA evaluation); defaults to 30s.
//   - LogLevel: logging verbosity ("debug", "info", "warn", "error"); defaults to "info".
type Config struct {
	DBPath         string
	PolicyDir      string
	MaxHops        int
	Offline        bool
	RequestTimeout time.Duration
	LogLevel       string
}

// Load reads configuration from environment variables and returns a Config populated
// with typed values and safe defaults.
//
// Parameters:
//   - (none): all configuration is read from the process environment.
//
// Returns a Config with every field set to either the environment-supplied value or
// its documented default. Load never returns an error; malformed environment values
// are silently replaced with their defaults.
func Load() *Config {
	return &Config{
		DBPath:         envString("ACCESSGRAPH_DB", "accessgraph.db"),
		PolicyDir:      envString("ACCESSGRAPH_POLICY_DIR", "policy"),
		MaxHops:        envInt("ACCESSGRAPH_MAX_HOPS", 8),
		Offline:        envBool("ACCESSGRAPH_OFFLINE", true),
		RequestTimeout: envDuration("ACCESSGRAPH_REQUEST_TIMEOUT", 30*time.Second),
		LogLevel:       envString("ACCESSGRAPH_LOG_LEVEL", "info"),
	}
}

// envString returns the value of the named environment variable, or defaultVal
// if the variable is unset or empty.
func envString(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// envInt returns the integer value of the named environment variable, or defaultVal
// if the variable is unset, empty, or not a valid integer.
func envInt(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

// envBool returns the boolean value of the named environment variable, or defaultVal
// if the variable is unset, empty, or not parseable by strconv.ParseBool.
func envBool(key string, defaultVal bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return defaultVal
	}
	return b
}

// envDuration returns the time.Duration value of the named environment variable,
// parsed by time.ParseDuration, or defaultVal if the variable is unset, empty,
// or not a valid duration string.
func envDuration(key string, defaultVal time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultVal
	}
	return d
}
