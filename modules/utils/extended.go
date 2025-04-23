package utils

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Contains checks if a slice contains a string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ReadLines reads a file and returns the lines as a slice
func ReadLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// ExtractDOMSinks extracts DOM sinks from JavaScript code
func ExtractDOMSinks(body string) []string {
	var sinks []string
	
	// Common DOM XSS sinks
	patterns := []string{
		`document\.write\s*\(`,
		`\.innerHTML\s*=`,
		`\.outerHTML\s*=`,
		`\.insertAdjacentHTML\s*\(`,
		`\.createContextualFragment\s*\(`,
		`eval\s*\(`,
		`setTimeout\s*\(`,
		`setInterval\s*\(`,
		`location\s*=`,
		`location\.href\s*=`,
		`location\.replace\s*\(`,
		`location\.assign\s*\(`,
		`execScript\s*\(`,
		`window\.open\s*\(`,
		`document\.createElement\s*\(`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			if !Contains(sinks, match) {
				sinks = append(sinks, match)
			}
		}
	}
	
	return sinks
}

// ExtractDOMSources extracts DOM sources from JavaScript code
func ExtractDOMSources(body string) []string {
	var sources []string
	
	// Common DOM XSS sources
	patterns := []string{
		`location\.search`,
		`location\.hash`,
		`location\.href`,
		`document\.URL`,
		`document\.documentURI`,
		`document\.referrer`,
		`window\.name`,
		`document\.cookie`,
		`localStorage`,
		`sessionStorage`,
		`getParameter\s*\([\"'](\w+)[\"']\)`,
		`URLSearchParams`,
		`get\s*\([\"'](\w+)[\"']\)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			if !Contains(sources, match) {
				sources = append(sources, match)
			}
		}
	}
	
	return sources
}

// ExtractURLsFromHTML extracts URLs from HTML
func ExtractURLsFromHTML(body, baseURL string) []string {
	var urls []string
	
	// Extract href attributes
	hrefRegex := regexp.MustCompile(`href=["'](.*?)["']`)
	hrefMatches := hrefRegex.FindAllStringSubmatch(body, -1)
	for _, match := range hrefMatches {
		if len(match) > 1 {
			extractedURL := match[1]
			if !strings.HasPrefix(extractedURL, "#") && !strings.HasPrefix(extractedURL, "javascript:") {
				// Resolve relative URLs
				if !strings.HasPrefix(extractedURL, "http") {
					parsedBase, err := url.Parse(baseURL)
					if err == nil {
						parsedURL, err := url.Parse(extractedURL)
						if err == nil {
							extractedURL = parsedBase.ResolveReference(parsedURL).String()
						}
					}
				}
				if !Contains(urls, extractedURL) {
					urls = append(urls, extractedURL)
				}
			}
		}
	}
	
	// Extract src attributes
	srcRegex := regexp.MustCompile(`src=["'](.*?)["']`)
	srcMatches := srcRegex.FindAllStringSubmatch(body, -1)
	for _, match := range srcMatches {
		if len(match) > 1 {
			extractedURL := match[1]
			if !strings.HasPrefix(extractedURL, "data:") && !strings.HasPrefix(extractedURL, "javascript:") {
				// Resolve relative URLs
				if !strings.HasPrefix(extractedURL, "http") {
					parsedBase, err := url.Parse(baseURL)
					if err == nil {
						parsedURL, err := url.Parse(extractedURL)
						if err == nil {
							extractedURL = parsedBase.ResolveReference(parsedURL).String()
						}
					}
				}
				if !Contains(urls, extractedURL) {
					urls = append(urls, extractedURL)
				}
			}
		}
	}
	
	// Extract form action attributes
	actionRegex := regexp.MustCompile(`action=["'](.*?)["']`)
	actionMatches := actionRegex.FindAllStringSubmatch(body, -1)
	for _, match := range actionMatches {
		if len(match) > 1 {
			extractedURL := match[1]
			if !strings.HasPrefix(extractedURL, "javascript:") {
				// Resolve relative URLs
				if !strings.HasPrefix(extractedURL, "http") {
					parsedBase, err := url.Parse(baseURL)
					if err == nil {
						parsedURL, err := url.Parse(extractedURL)
						if err == nil {
							extractedURL = parsedBase.ResolveReference(parsedURL).String()
						}
					}
				}
				if !Contains(urls, extractedURL) {
					urls = append(urls, extractedURL)
				}
			}
		}
	}
	
	return urls
}

// DetectWAF detects if a website is protected by a WAF
func DetectWAF(resp *http.Response) (bool, string) {
	if resp == nil {
		return false, ""
	}
	
	// Check response headers for WAF signatures
	headers := resp.Header
	
	// Cloudflare
	if _, ok := headers["Cf-Ray"]; ok {
		return true, "Cloudflare"
	}
	
	// Akamai
	if _, ok := headers["X-Akamai-Transformed"]; ok {
		return true, "Akamai"
	}
	
	// Imperva/Incapsula
	if _, ok := headers["X-Iinfo"]; ok {
		return true, "Imperva/Incapsula"
	}
	
	// F5 BIG-IP ASM
	if _, ok := headers["X-WA-Info"]; ok {
		return true, "F5 BIG-IP ASM"
	}
	
	// ModSecurity
	if server := headers.Get("Server"); strings.Contains(server, "ModSecurity") {
		return true, "ModSecurity"
	}
	
	// AWS WAF
	if _, ok := headers["X-Amzn-Trace-Id"]; ok {
		return true, "AWS WAF"
	}
	
	// Sucuri
	if _, ok := headers["X-Sucuri-ID"]; ok {
		return true, "Sucuri"
	}
	
	// Wordfence
	if _, ok := headers["X-Wordfence-Block"]; ok {
		return true, "Wordfence"
	}
	
	// Check for generic WAF behavior in response body
	body, err := ReadResponseBody(resp)
	if err == nil {
		// Common WAF block messages
		wafPatterns := []string{
			"blocked by security rules",
			"security violation",
			"access denied",
			"blocked by firewall",
			"suspicious activity",
			"security check",
			"attack detected",
			"malicious request",
		}
		
		for _, pattern := range wafPatterns {
			if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
				return true, "Generic WAF"
			}
		}
	}
	
	return false, ""
}

// ExtractCSPHeader extracts and parses the Content-Security-Policy header
func ExtractCSPHeader(resp *http.Response) (string, map[string]string) {
	if resp == nil {
		return "", nil
	}
	
	cspHeader := resp.Header.Get("Content-Security-Policy")
	if cspHeader == "" {
		cspHeader = resp.Header.Get("X-Content-Security-Policy") // Legacy header
	}
	
	if cspHeader == "" {
		return "", nil
	}
	
	// Parse CSP directives
	directives := make(map[string]string)
	parts := strings.Split(cspHeader, ";")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		directiveParts := strings.SplitN(part, " ", 2)
		if len(directiveParts) == 2 {
			directive := strings.TrimSpace(directiveParts[0])
			value := strings.TrimSpace(directiveParts[1])
			directives[directive] = value
		} else if len(directiveParts) == 1 {
			directive := strings.TrimSpace(directiveParts[0])
			directives[directive] = ""
		}
	}
	
	return cspHeader, directives
}

// IsCSPVulnerable checks if a CSP policy is vulnerable
func IsCSPVulnerable(directives map[string]string) (bool, string) {
	if directives == nil || len(directives) == 0 {
		return true, "No CSP policy found"
	}
	
	// Check for unsafe-inline in script-src
	if scriptSrc, ok := directives["script-src"]; ok {
		if strings.Contains(scriptSrc, "'unsafe-inline'") {
			return true, "script-src allows 'unsafe-inline'"
		}
	} else if defaultSrc, ok := directives["default-src"]; ok {
		if strings.Contains(defaultSrc, "'unsafe-inline'") {
			return true, "default-src allows 'unsafe-inline'"
		}
	} else {
		return true, "No script-src or default-src directive found"
	}
	
	// Check for unsafe-eval in script-src
	if scriptSrc, ok := directives["script-src"]; ok {
		if strings.Contains(scriptSrc, "'unsafe-eval'") {
			return true, "script-src allows 'unsafe-eval'"
		}
	} else if defaultSrc, ok := directives["default-src"]; ok {
		if strings.Contains(defaultSrc, "'unsafe-eval'") {
			return true, "default-src allows 'unsafe-eval'"
		}
	}
	
	// Check for wildcard domains
	if scriptSrc, ok := directives["script-src"]; ok {
		if strings.Contains(scriptSrc, "*.") || scriptSrc == "*" {
			return true, "script-src contains wildcard domain"
		}
	}
	
	// Check for known bypass domains
	bypassDomains := []string{
		"ajax.googleapis.com",
		"cdnjs.cloudflare.com",
		"code.jquery.com",
		"jsdelivr.net",
		"unpkg.com",
	}
	
	if scriptSrc, ok := directives["script-src"]; ok {
		for _, domain := range bypassDomains {
			if strings.Contains(scriptSrc, domain) {
				return true, fmt.Sprintf("script-src contains potentially bypassable domain: %s", domain)
			}
		}
	}
	
	return false, ""
}
