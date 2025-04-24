package optimization

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	// TODO: Update these imports after refactoring or providing the correct package paths.
	// import "github.com/ibrahimsql/aether/v2/internal/har"
	// import "github.com/ibrahimsql/aether/v2/pkg/model"
)

// GenerateNewRequest is make http.Cilent
func GenerateNewRequest(url, body string, options interface{}) *http.Request {
	req, _ := http.NewRequest("GET", url, nil)
	// req = har.AddMessageIDToRequest(req)
	// Add the Accept header like browsers do.
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")

	if options != nil {
		d := []byte(body)
		req, _ = http.NewRequest("POST", url, bytes.NewBuffer(d))
		// req = har.AddMessageIDToRequest(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(options.([]string)) > 0 {
		for _, v := range options.([]string) {
			h := strings.Split(v, ": ")
			if len(h) > 1 {
				req.Header.Set(h[0], h[1])
			}
		}
	}
	if options.(map[string]string)["Cookie"] != "" {
		req.Header.Set("Cookie", options.(map[string]string)["Cookie"])
	}
	if options.(map[string]string)["UserAgent"] != "" {
		req.Header.Set("User-Agent", options.(map[string]string)["UserAgent"])
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}
	if options.(map[string]string)["Method"] != "" {
		req.Method = options.(map[string]string)["Method"]
	}
	if options.(map[string]string)["CookieFromRaw"] != "" {
		rawFile := options.(map[string]string)["CookieFromRaw"]
		rF, err := os.Open(rawFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			rd := bufio.NewReader(rF)
			rq, err := http.ReadRequest(rd)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			} else {
				req.Header.Set("Cookie", GetRawCookie(rq.Cookies()))
			}
		}
	}
	return req
}

// GetRawCookie gets cookie from raw request
func GetRawCookie(cookies []*http.Cookie) string {
	var rawCookies []string
	for _, c := range cookies {
		e := fmt.Sprintf("%s=%s", c.Name, c.Value)
		rawCookies = append(rawCookies, e)
	}
	return strings.Join(rawCookies, "; ")
}

// MakeHeaderQuery is generate http query with custom header
func MakeHeaderQuery(target, hn, hv string, options interface{}) (*http.Request, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = "toBlind"
	tempMap["payload"] = hv
	tempMap["param"] = "thisisheadertesting"
	req, _ := http.NewRequest("GET", target, nil)
	// req = har.AddMessageIDToRequest(req)
	if options != nil {
		d := []byte("")
		req, _ = http.NewRequest("POST", target, bytes.NewBuffer(d))
		// req = har.AddMessageIDToRequest(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(options.([]string)) > 0 {
		for _, v := range options.([]string) {
			h := strings.Split(v, ": ")
			if len(h) > 1 {
				req.Header.Set(h[0], h[1])
			}
		}
	}

	if options.(map[string]string)["Cookie"] != "" {
		req.Header.Set("Cookie", options.(map[string]string)["Cookie"])
	}
	if options.(map[string]string)["UserAgent"] != "" {
		req.Header.Set("User-Agent", options.(map[string]string)["UserAgent"])
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}
	if options.(map[string]string)["Method"] != "" {
		req.Method = options.(map[string]string)["Method"]
	}
	req.Header.Set(hn, hv)
	return req, tempMap
}

// MakeRequestQuery is generate http query with custom parameters
func MakeRequestQuery(target, param, payload, ptype string, pAction string, pEncode string, options interface{}) (*http.Request, map[string]string) {

	tempMap := make(map[string]string)
	tempMap["type"] = ptype
	tempMap["action"] = pAction
	tempMap["encode"] = pEncode
	tempMap["payload"] = payload
	tempMap["param"] = param

	u, _ := url.Parse(target)

	var tempParam string
	var tempParamBody string
	if options == nil {
		tempParam = u.RawQuery // ---> GET
	} else {
		tempParam = u.RawQuery       // ---> GET
		tempParamBody = options.(map[string]string)["Data"] // ---> POST
	}

	paramList, _ := url.ParseQuery(tempParam)
	paramListBody, _ := url.ParseQuery(tempParamBody)

	//What we should do to the payload?
	switch tempMap["encode"] {
	case "urlEncode":
		payload = UrlEncode(payload)
		break

	case "urlDoubleEncode":
		payload = (UrlEncode(payload))
		break

	case "htmlEncode":
		payload = template.HTMLEscapeString(payload)
		break

	default:
		break
	}

	// We first check if the parameter exist and then "append or replace" the value
	if strings.Contains(ptype, "FORM") {
		if val, ok := paramListBody[tempMap["param"]]; ok {
			if tempMap["action"] == "toAppend" {
				paramListBody[tempMap["param"]][0] = val[0] + payload
			} else { //toReplace lies here
				paramListBody[tempMap["param"]][0] = payload
			}
		} else {
			//if the parameter doesn't exist, is added.
			paramListBody.Add(tempMap["param"], payload)
		}

		var rst *http.Request
		rst = GenerateNewRequest(u.String(), paramListBody.Encode(), options)
		return rst, tempMap
	} else {
		// PA-URL
		if val, ok := paramList[tempMap["param"]]; ok {
			if tempMap["action"] == "toAppend" {
				paramList[tempMap["param"]][0] = val[0] + payload
			} else { //toReplace lies here
				paramList[tempMap["param"]][0] = payload
			}
		} else {
			//if the parameter doesn't exist, is added.
			paramList.Add(tempMap["param"], payload)
		}

		var rst *http.Request
		u.RawQuery = paramList.Encode()
		rst = GenerateNewRequest(u.String(), paramListBody.Encode(), options)
		return rst, tempMap
	}
}

// Optimization is remove payload included badchar
func Optimization(payload string, badchars []string) bool {
	for _, v := range badchars {
		if strings.Contains(payload, v) {
			return false
		}
	}
	return true
}

// UrlEncode is custom url encoder for double url encoding
func UrlEncode(s string) (result string) {
	for _, c := range s {
		if c <= 0x7f { // single byte
			result += fmt.Sprintf("%%%X", c)
		} else if c > 0x1fffff { // quaternary byte
			result += fmt.Sprintf("%%%X%%%X%%%X%%%X",
				0xf0+((c&0x1c0000)>>18),
				0x80+((c&0x3f000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else if c > 0x7ff { // triple byte
			result += fmt.Sprintf("%%%X%%%X%%%X",
				0xe0+((c&0xf000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else { // double byte
			result += fmt.Sprintf("%%%X%%%X",
				0xc0+((c&0x7c0)>>6),
				0x80+(c&0x3f),
			)
		}
	}

	return result
}

// TODO: Update these imports after refactoring or providing the correct package paths.
// TODO: The following usages of 'model' and 'har' are commented out due to missing imports. Update after refactoring.
