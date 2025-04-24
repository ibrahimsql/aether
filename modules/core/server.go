package core

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/ibrahimsql/aetherxss/modules/config"
	"github.com/ibrahimsql/aetherxss/modules/scanner"
)

// Server represents the AetherXSS server
type Server struct {
	config *config.Config
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config) *Server {
	return &Server{
		config: cfg,
	}
}

// Start starts the server
func (s *Server) Start() {
	addr := fmt.Sprintf("%s:%d", s.config.ServerHost, s.config.ServerPort)
	
	// Register handlers
	http.HandleFunc("/", s.indexHandler)
	http.HandleFunc("/scan", s.scanHandler)
	http.HandleFunc("/blind", s.blindHandler)
	
	// Start server
	fmt.Printf("Starting server on %s...\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// indexHandler handles the index page
func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>AetherXSS Scanner</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #333;
        }
        form {
            background-color: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], select {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        input[type="checkbox"] {
            margin-right: 5px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .option-group {
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <h1>AetherXSS Scanner</h1>
    <form action="/scan" method="POST">
        <label for="url">URL to scan:</label>
        <input type="text" id="url" name="url" placeholder="https://example.com" required>
        
        <div class="option-group">
            <label>Scanner Options:</label>
            <div>
                <input type="checkbox" id="param-mining" name="param-mining">
                <label for="param-mining">Parameter Mining</label>
            </div>
            <div>
                <input type="checkbox" id="blind-xss" name="blind-xss">
                <label for="blind-xss">Blind XSS</label>
            </div>
            <div>
                <input type="checkbox" id="dom-xss" name="dom-xss">
                <label for="dom-xss">DOM XSS</label>
            </div>
            <div>
                <input type="checkbox" id="follow-redirects" name="follow-redirects" checked>
                <label for="follow-redirects">Follow Redirects</label>
            </div>
        </div>
        
        <label for="threads">Threads:</label>
        <input type="number" id="threads" name="threads" value="5" min="1" max="50">
        
        <label for="timeout">Timeout (seconds):</label>
        <input type="number" id="timeout" name="timeout" value="10" min="1" max="60">
        
        <label for="output-format">Output Format:</label>
        <select id="output-format" name="output-format">
            <option value="plain">Plain</option>
            <option value="json">JSON</option>
            <option value="jsonl">JSONL</option>
        </select>
        
        <button type="submit">Start Scan</button>
    </form>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// scanHandler handles the scan request
func (s *Server) scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	
	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	// Get parameters
	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}
	
	// Create configuration
	cfg := &config.Config{
		URL:             url,
		OutputFormat:    r.FormValue("output-format"),
		ParamMining:     r.FormValue("param-mining") != "",
		BlindXSS:        r.FormValue("blind-xss") != "",
		DOMXSS:          r.FormValue("dom-xss") != "",
		FollowRedirects: r.FormValue("follow-redirects") != "",
	}
	
	// Parse threads
	if threads := r.FormValue("threads"); threads != "" {
		if t, err := strconv.Atoi(threads); err == nil {
			cfg.Threads = t
		}
	}
	
	// Parse timeout
	if timeout := r.FormValue("timeout"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil {
			cfg.Timeout = t
		}
	}
	
	// Run scanner
	scanner := scanner.NewScanner(cfg)
	result := scanner.ScanURL(url)
	
	// Return result
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(result.ToJSON()))
}

// blindHandler handles blind XSS callbacks
func (s *Server) blindHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request
	log.Printf("Blind XSS callback from %s", r.RemoteAddr)
	
	// Get parameters
	domain := r.URL.Query().Get("d")
	cookie := r.URL.Query().Get("c")
	location := r.URL.Query().Get("l")
	
	// Log the parameters
	log.Printf("Domain: %s", domain)
	log.Printf("Cookie: %s", cookie)
	log.Printf("Location: %s", location)
	
	// Return success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
