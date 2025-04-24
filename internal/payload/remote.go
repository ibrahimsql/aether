package payload

import (
	"encoding/json"
	"io"
	"net/http"
)

// Asset is type of Assets
type Asset struct {
	Line string
	Size string
}

// GetPortswiggerPayloadWithSize is exported interface
func GetPortswiggerPayloadWithSize() ([]string, int) {
	lst, _, _ := GetPortswiggerPayload()
	return lst, len(lst)
}

// GetPayloaaetherxssPayloadWithSize is exported interface
func GetPayloaaetherxssPayloadWithSize() ([]string, int) {
	lst, _, _ := GetPayloaaetherxssPayload()
	return lst, len(lst)
}

// getAssetIbrahimsql is pull data and information for remote payloads
func getAssetIbrahimsql(apiEndpoint, dataEndpoint string) ([]string, string, string) {
	apiLink := "https://assets.ibrahimsql.com/" + apiEndpoint
	dataLink := "https://assets.ibrahimsql.com/" + dataEndpoint
	// Get Info JSON
	apiResp, err := http.Get(apiLink)
	if err != nil {
		var t []string
		return t, "", ""
	}
	defer apiResp.Body.Close()
	var asset Asset
	infoJSON, err := io.ReadAll(apiResp.Body)
	json.Unmarshal(infoJSON, &asset)

	// Get Payload Data
	dataResp, err := http.Get(dataLink)
	if err != nil {
		var t []string
		return t, "", ""
	}
	defer dataResp.Body.Close()
	payloadData, err := io.ReadAll(dataResp.Body)
	//payload := strings.Split(string(payloadData), `\n`)
	payload := splitLines(string(payloadData))

	return payload, asset.Line, asset.Size
}

// GetPortswiggerPayload is use for remote payloads (PortSwigger Cheatsheet)
func GetPortswiggerPayload() ([]string, string, string) {
	apiEndpoint := "xss-portswigger.json"
	dataEndpoint := "xss-portswigger.txt"
	payload, line, size := getAssetIbrahimsql(apiEndpoint, dataEndpoint)
	return payload, line, size
}

// GetPayloaaetherxssPayload is use for remote payloads (Payloaaetherxss)
func GetPayloaaetherxssPayload() ([]string, string, string) {
	apiEndpoint := "xss-aetherxss.json"
	dataEndpoint := "xss-aetherxss.txt"
	payload, line, size := getAssetIbrahimsql(apiEndpoint, dataEndpoint)
	return payload, line, size
}

// GetBurpWordlist is use for remote wordlist (BurpSuite's param-minior)
func GetBurpWordlist() ([]string, string, string) {
	apiEndpoint := "wl-params.json"
	dataEndpoint := "wl-params.txt"
	payload, line, size := getAssetHahwul(apiEndpoint, dataEndpoint)
	return payload, line, size
}

// GetAssetnoteWordlist is use for remote wordlist (assetnote)
func GetAssetnoteWordlist() ([]string, string, string) {
	apiEndpoint := "wl-assetnote-params.json"
	dataEndpoint := "wl-assetnote-params.txt"
	payload, line, size := getAssetHahwul(apiEndpoint, dataEndpoint)
	return payload, line, size
}
