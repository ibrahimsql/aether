package utils

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ibrahimsql/aetherxss/modules/payloads"
)

// ReadResponseBody reads the response body and returns it as a string
func ReadResponseBody(resp *http.Response) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("response is nil")
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	return string(body), nil
}

// IsXSSVulnerable checks if a response is vulnerable to XSS
func IsXSSVulnerable(body, payload string) bool {
	// Check if the payload is reflected in the response
	if strings.Contains(body, payload) {
		return true
	}
	
	// Check for encoded versions of the payload
	encodedPayload := strings.Replace(payload, "<", "&lt;", -1)
	encodedPayload = strings.Replace(encodedPayload, ">", "&gt;", -1)
	if strings.Contains(body, encodedPayload) {
		return false // Properly encoded, not vulnerable
	}
	
	// Check for partial reflections
	if strings.Contains(payload, "<script>") && strings.Contains(body, "<script>") && strings.Contains(body, "</script>") {
		return true
	}
	
	// Check for event handlers
	if strings.Contains(payload, "onerror=") && strings.Contains(body, "onerror=") {
		return true
	}
	
	// Check for javascript: URLs
	if strings.Contains(payload, "javascript:") && strings.Contains(body, "javascript:") {
		return true
	}
	
	return false
}

// IsDOMXSSVulnerable checks if a response is vulnerable to DOM-based XSS
func IsDOMXSSVulnerable(body, payload string) bool {
	// Check for common DOM sources
	domSources := []string{
		"document.URL",
		"document.documentURI",
		"document.URLUnencoded",
		"document.baseURI",
		"location",
		"location.href",
		"location.search",
		"location.hash",
		"location.pathname",
		"document.referrer",
		"window.name",
		"history.pushState",
		"history.replaceState",
		"localStorage",
		"sessionStorage",
		"document.cookie",
	}
	
	// Check for common DOM sinks
	domSinks := []string{
		"eval(",
		"setTimeout(",
		"setInterval(",
		"document.write(",
		"document.writeln(",
		"innerHTML",
		"outerHTML",
		"insertAdjacentHTML",
		"onevent",
		"document.createElement(",
		"document.createElementNS(",
		"jQuery.html(",
		"$(",
		".html(",
		".append(",
		".prepend(",
		".after(",
		".before(",
		".replaceWith(",
	}
	
	// Check for DOM sources
	for _, source := range domSources {
		if strings.Contains(body, source) {
			// Check for DOM sinks
			for _, sink := range domSinks {
				if strings.Contains(body, sink) {
					return true
				}
			}
		}
	}
	
	return false
}

// IsXSSVulnerableInContext checks if a response is vulnerable to XSS in a specific context
func IsXSSVulnerableInContext(body, payload, context string) bool {
	switch context {
	case "html":
		// Check for HTML context
		return strings.Contains(body, payload) && !strings.Contains(body, "&lt;") && !strings.Contains(body, "&gt;")
	case "attr":
		// Check for attribute context
		attrRegex := regexp.MustCompile(`<[^>]+\s+[^>]+="[^"]*` + regexp.QuoteMeta(payload) + `[^"]*"`)
		return attrRegex.MatchString(body)
	case "js":
		// Check for JavaScript context
		jsRegex := regexp.MustCompile(`<script[^>]*>[^<]*` + regexp.QuoteMeta(payload) + `[^<]*</script>`)
		return jsRegex.MatchString(body)
	case "url":
		// Check for URL context
		urlRegex := regexp.MustCompile(`href=["'][^"']*` + regexp.QuoteMeta(payload) + `[^"']*["']`)
		return urlRegex.MatchString(body)
	case "css":
		// Check for CSS context
		cssRegex := regexp.MustCompile(`<style[^>]*>[^<]*` + regexp.QuoteMeta(payload) + `[^<]*</style>`)
		return cssRegex.MatchString(body)
	default:
		return IsXSSVulnerable(body, payload)
	}
}

// ExtractFormParameters extracts parameters from HTML forms
func ExtractFormParameters(body string) []string {
	params := make(map[string]bool)
	
	// Extract form input names
	inputRegex := regexp.MustCompile(`<input[^>]+name=["']([^"']+)["']`)
	matches := inputRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = true
		}
	}
	
	// Extract textarea names
	textareaRegex := regexp.MustCompile(`<textarea[^>]+name=["']([^"']+)["']`)
	matches = textareaRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = true
		}
	}
	
	// Extract select names
	selectRegex := regexp.MustCompile(`<select[^>]+name=["']([^"']+)["']`)
	matches = selectRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = true
		}
	}
	
	return MapKeysToSlice(params)
}

// ExtractURLParameters extracts parameters from URLs in the HTML
func ExtractURLParameters(body string) []string {
	params := make(map[string]bool)
	
	// Extract URL parameters
	urlRegex := regexp.MustCompile(`[?&]([^=&]+)=`)
	matches := urlRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = true
		}
	}
	
	return MapKeysToSlice(params)
}

// ExtractJSParameters extracts parameters from JavaScript code
func ExtractJSParameters(body string) []string {
	params := make(map[string]bool)
	
	// Extract parameters from common JS patterns
	jsRegex := regexp.MustCompile(`['"]([\w\d_-]+)['"]:\s*`)
	matches := jsRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = true
		}
	}
	
	// Extract parameters from URL parsing
	jsUrlRegex := regexp.MustCompile(`\.getParameter\(['"]([^'"]+)['"]\)`)
	matches = jsUrlRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params[match[1]] = true
		}
	}
	
	return MapKeysToSlice(params)
}

// MapKeysToSlice converts a map's keys to a slice
func MapKeysToSlice(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	return result
}

// LoadPayloadsFromFile loads payloads from a file
func LoadPayloadsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		payload := strings.TrimSpace(scanner.Text())
		if payload != "" && !strings.HasPrefix(payload, "#") {
			payloads = append(payloads, payload)
		}
	}
	
	return payloads, scanner.Err()
}

// GetRandomUserAgent returns a random user agent
func GetRandomUserAgent() string {
	if len(payloads.UserAgents) == 0 {
		return "AetherXSS Scanner/1.0"
	}
	
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(payloads.UserAgents))))
	if err != nil {
		return payloads.UserAgents[0]
	}
	
	return payloads.UserAgents[n.Int64()]
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return fmt.Sprintf("%d", n)
		}
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// ToJSON converts an object to JSON
func ToJSON(v interface{}) (string, error) {
	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// CommandExists checks if a command exists
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// RunCommand runs a command
func RunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
