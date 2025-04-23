package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ibrahimsql/aether/modules/config"
	"github.com/ibrahimsql/aether/modules/core"
	"github.com/ibrahimsql/aether/modules/output"
	"github.com/ibrahimsql/aether/modules/portscan"
	"github.com/ibrahimsql/aether/modules/scanner"
	"github.com/ibrahimsql/aether/modules/utils"
)

func main() {
	// Parse command line arguments
	if len(os.Args) < 2 {
		printBanner()
		printUsage()
		return
	}

	// Define modes
	modes := map[string]func([]string){
		"url":         scanSingleURLMode,
		"file":        scanFileURLsMode,
		"pipe":        scanPipeMode,
		"server":      apiServerMode,
		"stored":      scanStoredXSSMode,
		"mcp":         multiContextPayloadMode,
		"version":     showVersionMode,
		"help":        showHelpMode,
		"install":     installAetherMode,
		"uninstall":   uninstallAetherMode,
		"portscanner": portScannerFastMode,
	}

	// Get the mode
	mode := strings.ToLower(os.Args[1])
	if modeFunc, exists := modes[mode]; exists {
		modeFunc(os.Args[2:])
	} else {
		fmt.Printf("Unknown mode: %s\n", mode)
		printUsage()
	}
}

// portScannerMode runs the fast port scanner mode with flags like naabu (minimal)
func portScannerFastMode(args []string) {
	fs := flag.NewFlagSet("portscanner", flag.ExitOnError)
	hostsStr := fs.String("host", "", "Target hosts (comma-separated)")
	hostsStrShort := fs.String("h", "", "Target hosts (comma-separated) [shorthand]")
	portsStr := fs.String("ports", "", "Ports to scan (e.g. 80,443,100-200)")
	portsStrShort := fs.String("p", "", "Ports to scan [shorthand]")
	allPorts := fs.Bool("all", false, "Scan all 65535 ports")
	nmapScript := fs.String("nmap-script", "", "Run nmap script on open ports (e.g. http-title)")
	threads := fs.Int("threads", 500, "Number of threads")
	threadsShort := fs.Int("t", 500, "Number of threads [shorthand]")
	timeout := fs.Int("timeout", 500, "Timeout per port in ms")
	timeoutShort := fs.Int("to", 500, "Timeout per port in ms [shorthand]")
	outputFormat := fs.String("o", "", "Write output to file (optional)")
	jsonOut := fs.Bool("json", false, "Write output in JSON format")
	fs.Usage = func() {
		fmt.Println(`Usage:\n  aether portscanner [flags]\n\nFlags:\n  -host, -h\tTarget hosts (comma-separated, required)\n  -ports, -p\tPorts to scan (e.g. 80,443,100-200) [optional]\n  -all\tScan all 65535 ports\n  -nmap-script\tRun nmap script on open ports (e.g. http-title)\n  -threads, -t\tNumber of threads (default 500)\n  -timeout, -to\tTimeout per port in ms (default 500)\n  -o\tWrite output to file (optional)\n  -json\tWrite output in JSON format (optional)\n  -help\tShow this message\n\nExamples:\n  aether portscanner -host scanme.nmap.org -p 80,443,8080 -t 1000 -to 1000\n  aether portscanner -host scanme.nmap.org -all\n  aether portscanner -host scanme.nmap.org -nmap-script http-title\n`)
	}
	fs.Parse(args)

	hostsVal := *hostsStr
	if hostsVal == "" {
		hostsVal = *hostsStrShort
	}
	if hostsVal == "" {
		fmt.Println("[!] Please specify at least one host with -host or -h")
		fs.Usage()
		return
	}
	hosts := strings.Split(hostsVal, ",")
	portsVal := *portsStr
	if portsVal == "" {
		portsVal = *portsStrShort
	}
	var ports []int
	if *allPorts {
		ports = portscan.AllPorts()
	} else if portsVal == "" {
		ports = portscan.CommonPorts()
	} else {
		ports = parsePortList(portsVal)
	}
	th := *threads
	if th == 500 {
		th = *threadsShort
	}
	to := *timeout
	if to == 500 {
		to = *timeoutShort
	}
	fps := portscan.NewFastPortScanner(th, time.Duration(to)*time.Millisecond)
	allResults := make([]portscan.ScanResult, 0)
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		fmt.Printf("Scanning %s with %d threads and %dms timeout...\n", host, th, to)
		results := fps.Scan(host, ports)
		allResults = append(allResults, results...)
		for _, r := range results {
			if r.Open {
				fmt.Printf("[+] %s:%d open\n", r.Host, r.Port)
				// nmap script desteği
				if *nmapScript != "" {
					fmt.Printf("    [*] Running nmap script: %s...\n", *nmapScript)
					out, err := portscan.RunNmapScript(r.Host, r.Port, *nmapScript)
					if err != nil {
						fmt.Printf("    [!] Nmap script error: %v\n", err)
					} else {
						fmt.Printf("    [nmap output]\n%s\n", out)
					}
				}
			}
		}
	}
	if *jsonOut {
		jsonBytes, _ := json.MarshalIndent(allResults, "", "  ")
		if *outputFormat != "" {
			ioutil.WriteFile(*outputFormat, jsonBytes, 0644)
		} else {
			fmt.Println(string(jsonBytes))
		}
	} else if *outputFormat != "" {
		var lines []string
		for _, r := range allResults {
			if r.Open {
				lines = append(lines, fmt.Sprintf("%s:%d open", r.Host, r.Port))
			}
		}
		ioutil.WriteFile(*outputFormat, []byte(strings.Join(lines, "\n")), 0644)
	}
}

// parsePortList parses a port string like 80,443,100-200 into []int
func parsePortList(s string) []int {
	set := make(map[int]struct{})
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				start, err1 := strconv.Atoi(bounds[0])
				end, err2 := strconv.Atoi(bounds[1])
				if err1 == nil && err2 == nil && start <= end {
					for p := start; p <= end; p++ {
						set[p] = struct{}{}
					}
				}
			}
		} else if p, err := strconv.Atoi(part); err == nil {
			set[p] = struct{}{}
		}
	}
	res := make([]int, 0, len(set))
	for p := range set {
		res = append(res, p)
	}
	if len(res) > 1 {
		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	}
	return res
}

func printBanner() {
	banner := `
===*                                *===                              
                      x+**x+        ·+*$@@@@@@@@@@@@$*+·        +x**++                          
                    ++==        +$@@@@@@$$$$$$$$$$$$@@@@@@$+        =*++                        
                  ++==      ·%@@@$$$$$$$$$$$$$$$$$$$$$$$$$$@@@%·      =*++                      
                ++==      =@@@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@@@=      ==++                    
                **o·    =@@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@@=    ·o**                    
              ++++    ·@@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@@·    ++++                  
              =*     +@$$$$$$$$$@@@@@$$$$$$$$$$$$$$$$$$@@@@@@$$$$$$$$@+     *=                  
            x+++    =@$$$$$$@@@@$%%%$$@@@$$$$$$$$$$@@@@$%%%%$@@@@$$$$$@=    +++x                
            +++·   ·@$$$$$@$x           o$@$$$$$$@@*            *@@$$$$@·   ·+++                
            ==     @$$$$$@·      ~xx      ·@$$$$@=      ·ox~      $@$$$$@     ==                
            ==     @$$$$@    +·        ~    @$$@+    x             $$$$$@     ==                
            ==    ·@$$$@+   *          *~   $$$@    *          @   x@$$$@·    ==                
            ==    ·@$$$@x   @    ·$    x    @$$$   ox    $     =   =@$$$@·    ==                
            ==    ·@$$$$$    *             *$$$@    *             ~@$$$$@·    ==                
            ==    ·@$$$$@*        ·*%~  ~*@@$$$$@         +%x·  +$@$$$$$@·    ==                
            ==    ·@$$$$$@@x          +@@@$$$$$$$@*           @@@$$$$$$$@·    ==                
            ==    ·@$$$$$$$@@@*x·    ~*$$$$$$$$$$$@@@%+~     +$$$$$$$$$$@·    ==                
            ==    ·@$$$$$$$$$$@@@@@@@@@$$$$$$$$$$$$$$@@@@@@@@@$$$$$$$$$$@·    ==                
            ==    ·@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@·    ==                
            ==    ·@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@·    ==                
            ==    ·@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@·    ==                
            ==    ~$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$~    ==                
            ==     @$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@     ==                
            ==     *@$$$$$$$$$$$$$@@@@@@$$$$$$$$$$$$@@@@@@$$$$$$$$$$$$$@*     ==                
            +++x    ·$@@@@$$$@@@@@*xoo+$@@@@@$$@@@@@$+oox*@@@@@$$$@@@@@~    x+++                
              **       ~=%$$$$*o          +%$$$$%+          o*$$$$%*o       **                 
`
	fmt.Println(banner)
	fmt.Println()
	fmt.Println(" Powerful open-source XSS scanner and utility focused on automation👻")
	fmt.Println()
	fmt.Println("  Version : aether v2.11.0")
	fmt.Println("  Help    : Run with -h to see all options and flags")
	fmt.Println()
}

func printUsage() {
	fmt.Println("Usage: aether [mode] [target] [flags]")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("  url      - Scan a single URL")
	fmt.Println("  file     - Scan URLs from a file")
	fmt.Println("  pipe     - Scan URLs from stdin")
	fmt.Println("  server   - Run as a server")
	fmt.Println("  stored   - Scan for stored XSS")
	fmt.Println("  mcp      - Multi-Context Payload mode")
	fmt.Println("  version  - Show version information")
	fmt.Println("  help     - Show help information")
	fmt.Println("  install  - Install Aether")
	fmt.Println("  uninstall - Uninstall Aether")
	fmt.Println()

	fmt.Println("Common flags:")
	fmt.Println("  --config         Path to configuration file")
	fmt.Println("  --output         Output format (plain, json, jsonl)")
	fmt.Println("  --verbose        Enable verbose output")
	fmt.Println("  --silent         Enable silent mode")
	fmt.Println("  --threads        Number of threads")
	fmt.Println("  --timeout        Timeout in seconds")
	fmt.Println("  --delay          Delay between requests in milliseconds")
	fmt.Println()

	fmt.Println("Feature flags:")
	fmt.Println("  --param-mining   Enable parameter mining")
	fmt.Println("  --blind-xss      Enable blind XSS testing")
	fmt.Println("  --dom-xss        Enable DOM XSS testing")
	fmt.Println("  --custom-alert   Custom alert value")
	fmt.Println("  --custom-payload Path to custom payload file")
	fmt.Println("  --follow-redirects Follow redirects")
	fmt.Println("  --proxy          Proxy URL (e.g., http://127.0.0.1:8080)")
	fmt.Println("  --headers        Custom headers (format: 'Name: Value,Name2: Value2')")
	fmt.Println("  --cookies        Custom cookies (format: 'name=value; name2=value2')")
	fmt.Println("  --method         HTTP method (GET, POST)")
	fmt.Println("  --data           POST data")
	fmt.Println()

	fmt.Println("Output flags:")
	fmt.Println("  --report         Path to save report")
	fmt.Println("  --har            Path to save HAR file")
	fmt.Println()

	fmt.Println("Examples:")
	fmt.Println("  aether url https://example.com --param-mining")
	fmt.Println("  aether file urls.txt --threads 10")
	fmt.Println("  cat urls.txt | aether pipe --output json")
	fmt.Println("  aether stored https://example.com --form-url https://example.com/form --result-url https://example.com/result")
	fmt.Println("  aether mcp https://example.com --payload \"<script>alert(1)</script>\" --contexts \"html,js\"")
}

func scanSingleURLMode(args []string) {
	if len(args) == 0 {
		fmt.Println("Error: URL is required")
		return
	}

	// Parse flags
	urlCmd := flag.NewFlagSet("url", flag.ExitOnError)

	// Common flags
	configFile := urlCmd.String("config", "", "Path to configuration file")
	outputFormat := urlCmd.String("output", "plain", "Output format (plain, json, jsonl)")
	verbose := urlCmd.Bool("verbose", false, "Enable verbose output")
	silent := urlCmd.Bool("silent", false, "Enable silent mode")

	// Scanner flags
	threads := urlCmd.Int("threads", 5, "Number of threads")
	timeout := urlCmd.Int("timeout", 10, "Timeout in seconds")
	delay := urlCmd.Int("delay", 0, "Delay between requests in milliseconds")

	// Feature flags
	paramMining := urlCmd.Bool("param-mining", false, "Enable parameter mining")
	blindXss := urlCmd.Bool("blind-xss", false, "Enable blind XSS testing")
	domXss := urlCmd.Bool("dom-xss", false, "Enable DOM XSS testing")
	customAlert := urlCmd.String("custom-alert", "", "Custom alert value")
	customPayload := urlCmd.String("custom-payload", "", "Path to custom payload file")
	followRedirects := urlCmd.Bool("follow-redirects", true, "Follow redirects")
	proxy := urlCmd.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	headers := urlCmd.String("headers", "", "Custom headers (format: 'Name: Value,Name2: Value2')")
	cookies := urlCmd.String("cookies", "", "Custom cookies (format: 'name=value; name2=value2')")
	method := urlCmd.String("method", "GET", "HTTP method (GET, POST)")
	data := urlCmd.String("data", "", "POST data")

	// Output flags
	reportPath := urlCmd.String("report", "", "Path to save report")
	harPath := urlCmd.String("har", "", "Path to save HAR file")

	// Parse flags
	urlCmd.Parse(args[1:])

	// Get URL
	url := args[0]

	// Create configuration
	cfg := &config.Config{
		URL:             url,
		ConfigFile:      *configFile,
		OutputFormat:    *outputFormat,
		Verbose:         *verbose,
		Silent:          *silent,
		Threads:         *threads,
		Timeout:         *timeout,
		Delay:           *delay,
		ParamMining:     *paramMining,
		BlindXSS:        *blindXss,
		DOMXSS:          *domXss,
		CustomAlert:     *customAlert,
		CustomPayload:   *customPayload,
		FollowRedirects: *followRedirects,
		Proxy:           *proxy,
		Headers:         *headers,
		Cookies:         *cookies,
		Method:          *method,
		Data:            *data,
		ReportPath:      *reportPath,
		HARPath:         *harPath,
	}

	// Load configuration from file if provided
	if *configFile != "" {
		if err := config.LoadFromFile(cfg, *configFile); err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			return
		}
	}

	// Run scanner
	scanner := scanner.NewScanner(cfg)
	result := scanner.ScanURL(url)

	// Output results
	outputter := output.NewOutputter(cfg)
	outputter.Output(result)
}

func scanFileURLsMode(args []string) {
	if len(args) == 0 {
		fmt.Println("Error: File path is required")
		return
	}

	// Parse flags
	fileCmd := flag.NewFlagSet("file", flag.ExitOnError)

	// Common flags
	configFile := fileCmd.String("config", "", "Path to configuration file")
	outputFormat := fileCmd.String("output", "plain", "Output format (plain, json, jsonl)")
	verbose := fileCmd.Bool("verbose", false, "Enable verbose output")
	silent := fileCmd.Bool("silent", false, "Enable silent mode")

	// Scanner flags
	threads := fileCmd.Int("threads", 5, "Number of threads")
	timeout := fileCmd.Int("timeout", 10, "Timeout in seconds")
	delay := fileCmd.Int("delay", 0, "Delay between requests in milliseconds")

	// Feature flags
	paramMining := fileCmd.Bool("param-mining", false, "Enable parameter mining")
	blindXss := fileCmd.Bool("blind-xss", false, "Enable blind XSS testing")
	domXss := fileCmd.Bool("dom-xss", false, "Enable DOM XSS testing")
	customAlert := fileCmd.String("custom-alert", "", "Custom alert value")
	customPayload := fileCmd.String("custom-payload", "", "Path to custom payload file")
	followRedirects := fileCmd.Bool("follow-redirects", true, "Follow redirects")
	proxy := fileCmd.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	headers := fileCmd.String("headers", "", "Custom headers (format: 'Name: Value,Name2: Value2')")
	cookies := fileCmd.String("cookies", "", "Custom cookies (format: 'name=value; name2=value2')")
	method := fileCmd.String("method", "GET", "HTTP method (GET, POST)")
	data := fileCmd.String("data", "", "POST data")

	// Output flags
	reportPath := fileCmd.String("report", "", "Path to save report")
	harPath := fileCmd.String("har", "", "Path to save HAR file")

	// Parse flags
	fileCmd.Parse(args[1:])

	// Get file path
	filePath := args[0]

	// Create configuration
	cfg := &config.Config{
		FilePath:        filePath,
		ConfigFile:      *configFile,
		OutputFormat:    *outputFormat,
		Verbose:         *verbose,
		Silent:          *silent,
		Threads:         *threads,
		Timeout:         *timeout,
		Delay:           *delay,
		ParamMining:     *paramMining,
		BlindXSS:        *blindXss,
		DOMXSS:          *domXss,
		CustomAlert:     *customAlert,
		CustomPayload:   *customPayload,
		FollowRedirects: *followRedirects,
		Proxy:           *proxy,
		Headers:         *headers,
		Cookies:         *cookies,
		Method:          *method,
		Data:            *data,
		ReportPath:      *reportPath,
		HARPath:         *harPath,
	}

	// Load configuration from file if provided
	if *configFile != "" {
		if err := config.LoadFromFile(cfg, *configFile); err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			return
		}
	}

	// Run scanner
	scanner := scanner.NewScanner(cfg)
	result := scanner.ScanFile(filePath)

	// Output results
	outputter := output.NewOutputter(cfg)
	outputter.Output(result)
}

func scanPipeMode(args []string) {
	// Parse flags
	pipeCmd := flag.NewFlagSet("pipe", flag.ExitOnError)

	// Common flags
	configFile := pipeCmd.String("config", "", "Path to configuration file")
	outputFormat := pipeCmd.String("output", "plain", "Output format (plain, json, jsonl)")
	verbose := pipeCmd.Bool("verbose", false, "Enable verbose output")
	silent := pipeCmd.Bool("silent", false, "Enable silent mode")

	// Scanner flags
	threads := pipeCmd.Int("threads", 5, "Number of threads")
	timeout := pipeCmd.Int("timeout", 10, "Timeout in seconds")
	delay := pipeCmd.Int("delay", 0, "Delay between requests in milliseconds")

	// Feature flags
	paramMining := pipeCmd.Bool("param-mining", false, "Enable parameter mining")
	blindXss := pipeCmd.Bool("blind-xss", false, "Enable blind XSS testing")
	domXss := pipeCmd.Bool("dom-xss", false, "Enable DOM XSS testing")
	customAlert := pipeCmd.String("custom-alert", "", "Custom alert value")
	customPayload := pipeCmd.String("custom-payload", "", "Path to custom payload file")
	followRedirects := pipeCmd.Bool("follow-redirects", true, "Follow redirects")
	proxy := pipeCmd.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	headers := pipeCmd.String("headers", "", "Custom headers (format: 'Name: Value,Name2: Value2')")
	cookies := pipeCmd.String("cookies", "", "Custom cookies (format: 'name=value; name2=value2')")
	method := pipeCmd.String("method", "GET", "HTTP method (GET, POST)")
	data := pipeCmd.String("data", "", "POST data")

	// Output flags
	reportPath := pipeCmd.String("report", "", "Path to save report")
	harPath := pipeCmd.String("har", "", "Path to save HAR file")

	// Parse flags
	pipeCmd.Parse(args)

	// Create configuration
	cfg := &config.Config{
		ConfigFile:      *configFile,
		OutputFormat:    *outputFormat,
		Verbose:         *verbose,
		Silent:          *silent,
		Threads:         *threads,
		Timeout:         *timeout,
		Delay:           *delay,
		ParamMining:     *paramMining,
		BlindXSS:        *blindXss,
		DOMXSS:          *domXss,
		CustomAlert:     *customAlert,
		CustomPayload:   *customPayload,
		FollowRedirects: *followRedirects,
		Proxy:           *proxy,
		Headers:         *headers,
		Cookies:         *cookies,
		Method:          *method,
		Data:            *data,
		ReportPath:      *reportPath,
		HARPath:         *harPath,
	}

	// Load configuration from file if provided
	if *configFile != "" {
		if err := config.LoadFromFile(cfg, *configFile); err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			return
		}
	}

	// Run scanner
	scanner := scanner.NewScanner(cfg)
	result := scanner.ScanPipe()

	// Output results
	outputter := output.NewOutputter(cfg)
	outputter.Output(result)
}

func apiServerMode(args []string) {
	// Parse flags
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)

	// Server flags
	port := serverCmd.Int("port", 8080, "Server port")
	host := serverCmd.String("host", "127.0.0.1", "Server host")

	// Common flags
	configFile := serverCmd.String("config", "", "Path to configuration file")
	outputFormat := serverCmd.String("output", "plain", "Output format (plain, json, jsonl)")
	verbose := serverCmd.Bool("verbose", false, "Enable verbose output")
	silent := serverCmd.Bool("silent", false, "Enable silent mode")

	// Scanner flags
	threads := serverCmd.Int("threads", 5, "Number of threads")
	timeout := serverCmd.Int("timeout", 10, "Timeout in seconds")
	delay := serverCmd.Int("delay", 0, "Delay between requests in milliseconds")

	// Feature flags
	paramMining := serverCmd.Bool("param-mining", false, "Enable parameter mining")
	blindXss := serverCmd.Bool("blind-xss", false, "Enable blind XSS testing")
	domXss := serverCmd.Bool("dom-xss", false, "Enable DOM XSS testing")

	// Parse flags
	serverCmd.Parse(args)

	// Create configuration
	cfg := &config.Config{
		ConfigFile:   *configFile,
		OutputFormat: *outputFormat,
		Verbose:      *verbose,
		Silent:       *silent,
		Threads:      *threads,
		Timeout:      *timeout,
		Delay:        *delay,
		ParamMining:  *paramMining,
		BlindXSS:     *blindXss,
		DOMXSS:       *domXss,
		ServerHost:   *host,
		ServerPort:   *port,
	}

	// Load configuration from file if provided
	if *configFile != "" {
		if err := config.LoadFromFile(cfg, *configFile); err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			return
		}
	}

	// Run server
	server := core.NewServer(cfg)
	server.Start()
}

func scanStoredXSSMode(args []string) {
	if len(args) == 0 {
		fmt.Println("Error: URL is required")
		return
	}

	// Parse flags
	storedCmd := flag.NewFlagSet("stored", flag.ExitOnError)

	// Common flags
	configFile := storedCmd.String("config", "", "Path to configuration file")
	outputFormat := storedCmd.String("output", "plain", "Output format (plain, json, jsonl)")
	verbose := storedCmd.Bool("verbose", false, "Enable verbose output")
	silent := storedCmd.Bool("silent", false, "Enable silent mode")

	// Scanner flags
	threads := storedCmd.Int("threads", 5, "Number of threads")
	timeout := storedCmd.Int("timeout", 10, "Timeout in seconds")
	delay := storedCmd.Int("delay", 0, "Delay between requests in milliseconds")

	// Stored XSS specific flags
	formURL := storedCmd.String("form-url", "", "URL of the form to test")
	resultURL := storedCmd.String("result-url", "", "URL where the input is displayed")

	// Parse flags
	storedCmd.Parse(args[1:])

	// Get URL
	url := args[0]

	// Create configuration
	cfg := &config.Config{
		URL:          url,
		ConfigFile:   *configFile,
		OutputFormat: *outputFormat,
		Verbose:      *verbose,
		Silent:       *silent,
		Threads:      *threads,
		Timeout:      *timeout,
		Delay:        *delay,
		FormURL:      *formURL,
		ResultURL:    *resultURL,
	}

	// Load configuration from file if provided
	if *configFile != "" {
		if err := config.LoadFromFile(cfg, *configFile); err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			return
		}
	}

	// Run scanner
	scanner := scanner.NewScanner(cfg)
	result := scanner.ScanStoredXSS(url, *formURL, *resultURL)

	// Output results
	outputter := output.NewOutputter(cfg)
	outputter.Output(result)
}

func multiContextPayloadMode(args []string) {
	if len(args) == 0 {
		fmt.Println("Error: URL is required")
		return
	}

	// Parse flags
	mcpCmd := flag.NewFlagSet("mcp", flag.ExitOnError)

	// Common flags
	configFile := mcpCmd.String("config", "", "Path to configuration file")
	outputFormat := mcpCmd.String("output", "plain", "Output format (plain, json, jsonl)")
	verbose := mcpCmd.Bool("verbose", false, "Enable verbose output")
	silent := mcpCmd.Bool("silent", false, "Enable silent mode")

	// MCP specific flags
	payload := mcpCmd.String("payload", "", "Payload to test")
	contexts := mcpCmd.String("contexts", "all", "Contexts to test (comma-separated: html,attr,js,url,css)")

	// Parse flags
	mcpCmd.Parse(args[1:])

	// Get URL
	url := args[0]

	// Create configuration
	cfg := &config.Config{
		URL:          url,
		ConfigFile:   *configFile,
		OutputFormat: *outputFormat,
		Verbose:      *verbose,
		Silent:       *silent,
		MCPPayload:   *payload,
		MCPContexts:  *contexts,
	}

	// Load configuration from file if provided
	if *configFile != "" {
		if err := config.LoadFromFile(cfg, *configFile); err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			return
		}
	}

	// Run scanner
	scanner := scanner.NewScanner(cfg)
	result := scanner.ScanMCP(url, *payload, *contexts)

	// Output results
	outputter := output.NewOutputter(cfg)
	outputter.Output(result)
}

func showVersionMode(args []string) {
	fmt.Println("Aether v2.0.0")
}

func showHelpMode(args []string) {
	printBanner()
	fmt.Println("Usage: aether [mode] [target] [flags]")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("  url      - Scan a single URL")
	fmt.Println("  file     - Scan URLs from a file")
	fmt.Println("  pipe     - Scan URLs from stdin")
	fmt.Println("  server   - Run as a server")
	fmt.Println("  stored   - Scan for stored XSS")
	fmt.Println("  mcp      - Multi-Context Payload mode")
	fmt.Println("  version  - Show version information")
	fmt.Println("  help     - Show help information")
	fmt.Println("  install  - Install Aether")
	fmt.Println("  uninstall - Uninstall Aether")
	fmt.Println()

	fmt.Println("Common flags:")
	fmt.Println("  --config         Path to configuration file")
	fmt.Println("  --output         Output format (plain, json, jsonl)")
	fmt.Println("  --verbose        Enable verbose output")
	fmt.Println("  --silent         Enable silent mode")
	fmt.Println("  --threads        Number of threads")
	fmt.Println("  --timeout        Timeout in seconds")
	fmt.Println("  --delay          Delay between requests in milliseconds")
	fmt.Println()

	fmt.Println("Feature flags:")
	fmt.Println("  --param-mining   Enable parameter mining")
	fmt.Println("  --blind-xss      Enable blind XSS testing")
	fmt.Println("  --dom-xss        Enable DOM XSS testing")
	fmt.Println("  --custom-alert   Custom alert value")
	fmt.Println("  --custom-payload Path to custom payload file")
	fmt.Println("  --follow-redirects Follow redirects")
	fmt.Println("  --proxy          Proxy URL (e.g., http://127.0.0.1:8080)")
	fmt.Println("  --headers        Custom headers (format: 'Name: Value,Name2: Value2')")
	fmt.Println("  --cookies        Custom cookies (format: 'name=value; name2=value2')")
	fmt.Println("  --method         HTTP method (GET, POST)")
	fmt.Println("  --data           POST data")
	fmt.Println()

	fmt.Println("Output flags:")
	fmt.Println("  --report         Path to save report")
	fmt.Println("  --har            Path to save HAR file")
	fmt.Println()

	fmt.Println("Examples:")
	fmt.Println("  aether url https://example.com --param-mining")
	fmt.Println("  aether file urls.txt --threads 10")
	fmt.Println("  cat urls.txt | aether pipe --output json")
	fmt.Println("  aether stored https://example.com --form-url https://example.com/form --result-url https://example.com/result")
	fmt.Println("  aether mcp https://example.com --payload \"<script>alert(1)</script>\" --contexts \"html,js\"")
}

func installAetherMode(args []string) {
	fmt.Println("Installing Aether...")

	// Check if Go is installed
	if !utils.CommandExists("go") {
		fmt.Println("Error: Go is not installed. Please install Go first.")
		return
	}

	// Build the binary
	fmt.Println("Building Aether...")
	if err := utils.RunCommand("go", "build", "-o", "aether"); err != nil {
		fmt.Printf("Error building Aether: %v\n", err)
		return
	}

	// Move the binary to /usr/local/bin
	fmt.Println("Installing Aether to /usr/local/bin...")
	if err := utils.RunCommand("sudo", "mv", "aether", "/usr/local/bin/"); err != nil {
		fmt.Printf("Error installing Aether: %v\n", err)
		return
	}

	fmt.Println("Aether installed successfully!")
}

func uninstallAetherMode(args []string) {
	fmt.Println("Uninstalling Aether...")

	// Remove the binary from /usr/local/bin
	if err := utils.RunCommand("sudo", "rm", "/usr/local/bin/aether"); err != nil {
		fmt.Printf("Error uninstalling Aether: %v\n", err)
		return
	}

	fmt.Println("Aether uninstalled successfully!")
}
