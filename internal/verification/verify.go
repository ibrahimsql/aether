package verification

import (
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// VerifyReflectionWithLine checks reflected param for mining
func VerifyReflectionWithLine(body, payload string) (bool, int) {
	bodyArray := strings.Split(body, "\n")
	for l, v := range bodyArray {
		if strings.Contains(v, payload) {
			return true, l + 1
		}
	}
	return false, 0
}

// VerifyReflection checks reflected param for xss and mining
func VerifyReflection(body, payload string) bool {
	return strings.Contains(body, payload)
}

// VerifyDOM checks success inject on code
func VerifyDOM(s string) bool {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(s))
	if err != nil {
		fmt.Println(err)
		return false
	}

	// Check for elements with class "aetherxss" or id "aetherxss"
	return doc.Find(".aetherxss").Length() > 0 || doc.Find("#aetherxss").Length() > 0
}
