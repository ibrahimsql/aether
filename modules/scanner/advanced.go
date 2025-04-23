package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ibrahimsql/aether/modules/payloads"
	"github.com/ibrahimsql/aether/modules/utils"
)

// detectWAF detects if a website is protected by a WAF
func (s *Scanner) detectWAF(targetURL string) {
	s.printVerbose(fmt.Sprintf("Detecting WAF for %s", targetURL))
	
	// Send a request with a basic XSS payload to trigger WAF
	testURL := targetURL
	if !strings.Contains(targetURL, "?") {
		testURL = targetURL + "?xss=<script>alert(1)</script>"
	} else {
		testURL = targetURL + "&xss=<script>alert(1)</script>"
	}
	
	resp, err := s.sendRequest("GET", testURL, "")
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error detecting WAF: %v", err))
		return
	}
	
	// Detect WAF from response
	detected, wafName := utils.DetectWAF(resp)
	s.wafDetected = detected
	s.detectedWAF = wafName
	
	if detected {
		s.printVerbose(fmt.Sprintf("WAF detected: %s", wafName))
	} else {
		s.printVerbose("No WAF detected")
	}
}

// analyzeCSP analyzes the Content Security Policy of a website
func (s *Scanner) analyzeCSP(targetURL string) *CSPInfo {
	s.printVerbose(fmt.Sprintf("Analyzing CSP for %s", targetURL))
	
	resp, err := s.sendRequest("GET", targetURL, "")
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error analyzing CSP: %v", err))
		return &CSPInfo{Vulnerable: false}
	}
	
	// Extract CSP header
	cspHeader, directives := utils.ExtractCSPHeader(resp)
	if cspHeader == "" {
		s.printVerbose("No CSP header found")
		return &CSPInfo{
			Vulnerable: true,
			BypassVector: "No CSP header found",
		}
	}
	
	// Check if CSP is vulnerable
	vulnerable, bypassVector := utils.IsCSPVulnerable(directives)
	
	cspInfo := &CSPInfo{
		Header: cspHeader,
		Directives: directives,
		Vulnerable: vulnerable,
		Bypassable: vulnerable,
		BypassVector: bypassVector,
	}
	
	if vulnerable {
		s.printVerbose(fmt.Sprintf("Vulnerable CSP found: %s", bypassVector))
		s.incrementStat("CSPBypassed")
	} else {
		s.printVerbose("CSP appears to be secure")
	}
	
	return cspInfo
}

// crawlWebsite crawls a website to find additional URLs
func (s *Scanner) crawlWebsite(targetURL string, depth int) []string {
	s.printVerbose(fmt.Sprintf("Crawling website %s with depth %d", targetURL, depth))
	
	// Initialize visited URLs map and URLs to crawl
	visited := make(map[string]bool)
	var crawledURLs []string
	
	// Add target URL to crawled URLs
	crawledURLs = append(crawledURLs, targetURL)
	visited[targetURL] = true
	
	// Parse target URL to get domain
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error parsing URL: %v", err))
		return crawledURLs
	}
	domain := parsedURL.Hostname()
	
	// Queue for BFS crawling
	queue := []struct {
		url   string
		depth int
	}{
		{targetURL, 0},
	}
	
	// BFS crawling
	for len(queue) > 0 {
		// Get next URL from queue
		current := queue[0]
		queue = queue[1:]
		
		// Skip if depth limit reached
		if current.depth >= depth {
			continue
		}
		
		// Send request
		resp, err := s.sendRequest("GET", current.url, "")
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error crawling %s: %v", current.url, err))
			continue
		}
		
		// Read response body
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
			continue
		}
		
		// Extract URLs from HTML
		urls := utils.ExtractURLsFromHTML(body, current.url)
		
		// Add URLs to queue
		for _, u := range urls {
			// Parse URL
			parsedURL, err := url.Parse(u)
			if err != nil {
				continue
			}
			
			// Skip if different domain
			if parsedURL.Hostname() != domain {
				continue
			}
			
			// Skip if already visited
			if visited[u] {
				continue
			}
			
			// Add to visited and queue
			visited[u] = true
			crawledURLs = append(crawledURLs, u)
			queue = append(queue, struct {
				url   string
				depth int
			}{u, current.depth + 1})
		}
	}
	
	return crawledURLs
}

// mineDOMParameters mines parameters from DOM
func (s *Scanner) mineDOMParameters(targetURL string) []string {
	s.printVerbose(fmt.Sprintf("Mining DOM parameters for %s", targetURL))
	
	var params []string
	
	// Send request
	resp, err := s.sendRequest("GET", targetURL, "")
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error mining DOM parameters: %v", err))
		return params
	}
	
	// Read response body
	body, err := utils.ReadResponseBody(resp)
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
		return params
	}
	
	// Extract DOM sources
	sources := utils.ExtractDOMSources(body)
	
	// Extract parameters from sources
	for _, source := range sources {
		// Extract parameter name from getParameter calls
		if strings.Contains(source, "getParameter") {
			re := regexp.MustCompile(`getParameter\s*\([\"'](\w+)[\"']\)`)
			matches := re.FindStringSubmatch(source)
			if len(matches) > 1 {
				param := matches[1]
				if !utils.Contains(params, param) {
					params = append(params, param)
				}
			}
		}
		
		// Extract parameter name from URLSearchParams.get calls
		if strings.Contains(source, "get") {
			re := regexp.MustCompile(`get\s*\([\"'](\w+)[\"']\)`)
			matches := re.FindStringSubmatch(source)
			if len(matches) > 1 {
				param := matches[1]
				if !utils.Contains(params, param) {
					params = append(params, param)
				}
			}
		}
	}
	
	return params
}

// testDOMXSS tests for DOM-based XSS
func (s *Scanner) testDOMXSS(targetURL, param string, vulnChan chan<- Vulnerability) {
	s.printVerbose(fmt.Sprintf("Testing DOM XSS for %s with parameter %s", targetURL, param))
	
	// Send request to get the page
	resp, err := s.sendRequest("GET", targetURL, "")
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error testing DOM XSS: %v", err))
		return
	}
	
	// Read response body
	body, err := utils.ReadResponseBody(resp)
	if err != nil {
		s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
		return
	}
	
	// Extract DOM sinks
	sinks := utils.ExtractDOMSinks(body)
	if len(sinks) == 0 {
		s.printVerbose("No DOM sinks found")
		return
	}
	
	// Test each DOM XSS payload
	for _, payload := range s.payloadMap["dom"] {
		// Construct test URL
		testURL := s.constructURL(targetURL, param, payload)
		
		// Send request
		resp, err := s.sendRequest("GET", testURL, "")
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error testing DOM XSS: %v", err))
			continue
		}
		
		// Read response body
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
			continue
		}
		
		// Check if vulnerable
		if utils.IsDOMXSSVulnerable(body, payload) {
			// Found vulnerability
			vuln := Vulnerability{
				Type:      "DOM XSS",
				URL:       testURL,
				Parameter: param,
				Evidence:  payload,
				Severity:  "High",
				Confidence: "Medium",
				Payload:   payload,
				Context:   "DOM",
			}
			
			// Send to channel
			vulnChan <- vuln
			
			// Increment stats
			s.incrementStat("VulnerableURLs")
			s.incrementStat("DOMXSSFound")
			
			// Print info
			s.printInfo(fmt.Sprintf("Found DOM XSS vulnerability: %s", testURL))
			
			// Break after finding first vulnerability
			break
		}
	}
}

// testHeader tests a header for XSS
func (s *Scanner) testHeader(targetURL, header string, vulnChan chan<- Vulnerability) {
	s.printVerbose(fmt.Sprintf("Testing header %s for XSS in %s", header, targetURL))
	
	// Test each XSS payload
	for _, payload := range payloads.XSSPayloads {
		// Create request
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error creating request: %v", err))
			continue
		}
		
		// Add header with payload
		req.Header.Set(header, payload)
		
		// Add cookies if configured
		if s.config.Cookies != "" {
			req.Header.Set("Cookie", s.config.Cookies)
		}
		
		// Add custom headers if configured
		if s.config.Headers != "" {
			headers := s.config.GetHeadersMap()
			for name, value := range headers {
				req.Header.Set(name, value)
			}
		}
		
		// Set user agent
		req.Header.Set("User-Agent", utils.GetRandomUserAgent())
		
		// Send request
		start := time.Now()
		resp, err := s.client.Do(req)
		// Süreyi ölçüp istatistiklere ekleyelim
		s.incrementStatValue("TotalRequestTime", time.Since(start).Milliseconds())
		
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error sending request: %v", err))
			s.incrementStat("FailedRequests")
			continue
		}
		
		// Read response body
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			s.printVerbose(fmt.Sprintf("Error reading response body: %v", err))
			continue
		}
		
		// Check if vulnerable
		if utils.IsXSSVulnerable(body, payload) {
			// Found vulnerability
			vuln := Vulnerability{
				Type:      "Reflected XSS (Header)",
				URL:       targetURL,
				Parameter: header,
				Evidence:  payload,
				Severity:  "High",
				Confidence: "Medium",
				Payload:   payload,
				Vector:    "HTTP Header",
			}
			
			// Send to channel
			vulnChan <- vuln
			
			// Increment stats
			s.incrementStat("VulnerableURLs")
			
			// Print info
			s.printInfo(fmt.Sprintf("Found XSS vulnerability in header %s: %s", header, targetURL))
			
			// Break after finding first vulnerability
			break
		}
	}
}

// autoExploit attempts to automatically exploit a vulnerability
func (s *Scanner) autoExploit(vuln Vulnerability) bool {
	s.printVerbose(fmt.Sprintf("Attempting to auto-exploit: %s", vuln.URL))
	
	// For now, just return true to indicate exploitation is possible
	// In a real implementation, this would attempt to exploit the vulnerability
	// and return true if successful
	
	return true
}
