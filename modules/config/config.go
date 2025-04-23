package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Config represents the configuration for the scanner
type Config struct {
	// General settings
	URL             string
	FilePath        string
	ConfigFile      string
	OutputFormat    string // plain, json, jsonl
	Verbose         bool
	Silent          bool
	Version         string

	// Scanner settings
	Threads         int
	Timeout         int
	Delay           int
	CrawlDepth      int
	Workers         int // Number of concurrent workers

	// Feature settings
	ParamMining     bool   // Enable parameter mining
	BlindXSS        bool   // Enable blind XSS testing
	DOMXSS          bool   // Enable DOM XSS testing
	CSPAnalysis     bool   // Enable CSP analysis
	Crawl           bool   // Enable web crawling
	FuzzHeaders     bool   // Enable header fuzzing
	AutoExploit     bool   // Enable auto exploitation
	FrameworkSpecific bool  // Enable framework-specific payloads
	CustomAlert     string // Custom alert value
	CustomPayload   string // Path to custom payload file
	CustomPayloads  []string // List of custom payloads
	FollowRedirects bool   // Follow redirects
	Proxy           string // Proxy URL
	Headers         string // Custom headers
	Cookies         string // Custom cookies
	Method          string // HTTP method (GET, POST)
	Data            string // POST data
	BlindCallback   string // Blind XSS callback URL
	BlindXSSCallback string // Alternative blind XSS callback URL
	RemotePayloads  string // URL to remote payloads
	RemoteWordlist  string // URL to remote wordlist
	UserAgent       string // Custom User-Agent
	WAFBypass       bool   // Enable WAF bypass techniques

	// Output settings
	ReportPath      string // Path to save report
	HARPath         string // Path to save HAR file
	JSONOutput      string // Path to save JSON output
	JSONLOutput     string // Path to save JSONL output

	// Server settings
	ServerHost      string // Server host
	ServerPort      int    // Server port
	ServerPath      string // Server path

	// Stored XSS settings
	FormURL         string // Form URL for stored XSS testing
	ResultURL       string // Result URL for stored XSS testing

	// MCP settings
	MCPPayload      string // Multi-Context Payload
	MCPContexts     string // Multi-Context Payload contexts

	// Callback settings
	CallbackURL     string // Callback URL

	// Mode settings
	Mode            string // Scan mode (url, file, pipe, server, stored, mcp)

	// Headless browser settings
	Headless        bool   // Use headless browser
	HeadlessTimeout int    // Headless browser timeout

	// Authentication settings
	BasicAuth       string // Basic authentication (username:password)
	BearerToken     string // Bearer token

	// Rate limiting
	RateLimit       int    // Requests per second
	RateBurst       int    // Maximum burst size
}

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(cfg *Config, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, cfg)
}

// SaveToFile saves configuration to a JSON file
func SaveToFile(cfg *Config, filePath string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

// GetHeadersMap converts the Headers string to a map
func (c *Config) GetHeadersMap() map[string]string {
	headers := make(map[string]string)
	if c.Headers == "" {
		return headers
	}

	parts := strings.Split(c.Headers, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return headers
}

// GetCookiesMap converts the Cookies string to a map
func (c *Config) GetCookiesMap() map[string]string {
	cookies := make(map[string]string)
	if c.Cookies == "" {
		return cookies
	}

	parts := strings.Split(c.Cookies, ";")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			cookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return cookies
}

// GetMCPContextsList converts the MCPContexts string to a slice
func (c *Config) GetMCPContextsList() []string {
	if c.MCPContexts == "" || c.MCPContexts == "all" {
		return []string{"html", "attr", "js", "url", "css"}
	}

	return strings.Split(c.MCPContexts, ",")
}
