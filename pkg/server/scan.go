package server

import (
	"strings"

	vlogger "github.com/ibrahimsql/aether/internal/logger"
	daether "github.com/ibrahimsql/aether/lib"
	"github.com/ibrahimsql/aether/pkg/model"
	scan "github.com/ibrahimsql/aether/pkg/scanning"
)

// ScanFromAPI is scanning aether with REST API
// @Summary scan
// @Description add aether scan
// @Accept  json
// @Produce  json
// @Param data body Req true "json data"
// @Success 200 {object} Res
// @Router /scan [post]
func ScanFromAPI(url string, rqOptions model.Options, options model.Options, sid string) {
	vLog := vlogger.GetLogger(options.Debug)
	target := daether.Target{
		URL:     url,
		Method:  rqOptions.Method,
		Options: rqOptions,
	}
	newOptions := aether.Initialize(target, target.Options)
	newOptions.Scan = options.Scan
	if rqOptions.Method != "" {
		newOptions.Method = options.Method
	} else {
		newOptions.Method = "GET"
	}
	escapedURL := cleanURL(url)
	vLog.WithField("data1", sid).Debug(escapedURL)
	vLog.WithField("data1", sid).Debug(newOptions)
	_, err := scan.Scan(url, newOptions, sid)
	if err != nil {
		vLog.WithField("data1", sid).Error("Scan failed for URL:", url, ": ", err)
		return
	}
	vLog.WithField("data1", sid).Info("Scan completed successfully")
}

// GetScan is get scan information
// @Summary scan
// @Description get scan info
// @Accept  json
// @Produce  json
// @Param scanid path string true "scan id"
// @Success 200 {object} Res
// @Router /scan/{scanid} [get]
func GetScan(sid string, options model.Options) model.Scan {
	return options.Scan[sid]
}

// GetScans is list of scan
// @Summary scan
// @Description show scan list
// @Accept  json
// @Produce  json
// @Success 200 {array} string
// @Router /scans [get]
func GetScans(options model.Options) []string {
	var scans []string
	for sid := range options.Scan {
		scans = append(scans, sid)
	}
	return scans
}

// cleanURL removes newline and carriage return characters from the URL
func cleanURL(url string) string {
	escapedURL := strings.Replace(url, "\n", "", -1)
	escapedURL = strings.Replace(escapedURL, "\r", "", -1)
	return escapedURL
}
