package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ibrahimsql/aether/modules/config"
	"github.com/ibrahimsql/aether/modules/scanner"
)

// Outputter represents the output handler
type Outputter struct {
	config *config.Config
}

// NewOutputter creates a new outputter instance
func NewOutputter(cfg *config.Config) *Outputter {
	return &Outputter{
		config: cfg,
	}
}

// Output outputs the scan result
func (o *Outputter) Output(result *scanner.Result) {
	switch strings.ToLower(o.config.OutputFormat) {
	case "json":
		o.outputJSON(result)
	case "jsonl":
		o.outputJSONL(result)
	default:
		o.outputPlain(result)
	}

	// Generate report if configured
	if o.config.ReportPath != "" {
		o.generateReport(result)
	}

	// Generate HAR file if configured
	if o.config.HARPath != "" {
		o.generateHAR(result)
	}
}

// outputPlain outputs the result in plain text format
func (o *Outputter) outputPlain(result *scanner.Result) {
	// Print banner
	fmt.Println("aether Scan Results")
	fmt.Println("=====================")

	// Print target
	fmt.Printf("Target: %s\n", result.Target)

	// Print scan time
	fmt.Printf("Scan started: %s\n", result.StartTime)
	fmt.Printf("Scan ended: %s\n", result.EndTime)
	fmt.Printf("Duration: %s\n", result.Duration)

	// Print stats
	fmt.Println("\nStatistics:")
	fmt.Printf("  Tested URLs: %d\n", result.Stats.TestedURLs)
	fmt.Printf("  Vulnerable URLs: %d\n", result.Stats.VulnerableURLs)
	fmt.Printf("  Failed Requests: %d\n", result.Stats.FailedRequests)
	fmt.Printf("  Parameters Found: %d\n", result.Stats.ParametersFound)

	// Print vulnerabilities
	fmt.Printf("\nVulnerabilities Found: %d\n", len(result.Vulnerabilities))
	if len(result.Vulnerabilities) > 0 {
		fmt.Println("\nDetails:")
		for i, vuln := range result.Vulnerabilities {
			fmt.Printf("\n[%d] %s\n", i+1, vuln.Type)
			fmt.Printf("  URL: %s\n", vuln.URL)
			fmt.Printf("  Parameter: %s\n", vuln.Parameter)
			fmt.Printf("  Evidence: %s\n", vuln.Evidence)
			fmt.Printf("  Severity: %s\n", vuln.Severity)
			fmt.Printf("  Confidence: %s\n", vuln.Confidence)
		}
	}
}

// outputJSON outputs the result in JSON format
func (o *Outputter) outputJSON(result *scanner.Result) {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Error generating JSON output: %v\n", err)
		return
	}

	fmt.Println(string(jsonData))
}

// outputJSONL outputs the result in JSONL format
func (o *Outputter) outputJSONL(result *scanner.Result) {
	// Output scan info
	scanInfo := map[string]interface{}{
		"type":       "scan_info",
		"target":     result.Target,
		"start_time": result.StartTime,
		"end_time":   result.EndTime,
		"duration":   result.Duration,
	}

	jsonData, err := json.Marshal(scanInfo)
	if err != nil {
		fmt.Printf("Error generating JSONL output: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))

	// Output stats
	statsInfo := map[string]interface{}{
		"type":             "stats",
		"tested_urls":      result.Stats.TestedURLs,
		"vulnerable_urls":  result.Stats.VulnerableURLs,
		"failed_requests":  result.Stats.FailedRequests,
		"parameters_found": result.Stats.ParametersFound,
	}

	jsonData, err = json.Marshal(statsInfo)
	if err != nil {
		fmt.Printf("Error generating JSONL output: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))

	// Output vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		vulnInfo := map[string]interface{}{
			"type":       "vulnerability",
			"vuln_type":  vuln.Type,
			"url":        vuln.URL,
			"parameter":  vuln.Parameter,
			"evidence":   vuln.Evidence,
			"severity":   vuln.Severity,
			"confidence": vuln.Confidence,
		}

		jsonData, err = json.Marshal(vulnInfo)
		if err != nil {
			fmt.Printf("Error generating JSONL output: %v\n", err)
			continue
		}
		fmt.Println(string(jsonData))
	}
}

// generateReport generates an HTML report
func (o *Outputter) generateReport(result *scanner.Result) {
	// Create HTML report
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>aether Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        .stat-box {
            background-color: #f8f9fa;
            border-left: 5px solid #3498db;
            padding: 10px 15px;
            margin: 10px;
            flex: 1;
            min-width: 200px;
        }
        .vulnerabilities {
            margin-bottom: 20px;
        }
        .vuln-item {
            background-color: #f8f9fa;
            border-left: 5px solid #e74c3c;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 5px 5px 0;
        }
        .high {
            border-left-color: #e74c3c;
        }
        .medium {
            border-left-color: #f39c12;
        }
        .low {
            border-left-color: #3498db;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        pre {
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>aether Scan Report</h1>
            <p>Generated on ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target:</strong> ` + result.Target + `</p>
            <p><strong>Scan Started:</strong> ` + result.StartTime + `</p>
            <p><strong>Scan Ended:</strong> ` + result.EndTime + `</p>
            <p><strong>Duration:</strong> ` + result.Duration + `</p>
        </div>
        
        <h2>Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>Tested URLs</h3>
                <p>` + fmt.Sprintf("%d", result.Stats.TestedURLs) + `</p>
            </div>
            <div class="stat-box">
                <h3>Vulnerable URLs</h3>
                <p>` + fmt.Sprintf("%d", result.Stats.VulnerableURLs) + `</p>
            </div>
            <div class="stat-box">
                <h3>Failed Requests</h3>
                <p>` + fmt.Sprintf("%d", result.Stats.FailedRequests) + `</p>
            </div>
            <div class="stat-box">
                <h3>Parameters Found</h3>
                <p>` + fmt.Sprintf("%d", result.Stats.ParametersFound) + `</p>
            </div>
        </div>
        
        <h2>Vulnerabilities Found (` + fmt.Sprintf("%d", len(result.Vulnerabilities)) + `)</h2>
        <div class="vulnerabilities">
`

	// Add vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		for i, vuln := range result.Vulnerabilities {
			severityClass := "medium"
			if strings.ToLower(vuln.Severity) == "high" {
				severityClass = "high"
			} else if strings.ToLower(vuln.Severity) == "low" {
				severityClass = "low"
			}

			html += `
            <div class="vuln-item ` + severityClass + `">
                <h3>[` + fmt.Sprintf("%d", i+1) + `] ` + vuln.Type + `</h3>
                <p><strong>URL:</strong> ` + vuln.URL + `</p>
                <p><strong>Parameter:</strong> ` + vuln.Parameter + `</p>
                <p><strong>Evidence:</strong> ` + vuln.Evidence + `</p>
                <p><strong>Severity:</strong> ` + vuln.Severity + `</p>
                <p><strong>Confidence:</strong> ` + vuln.Confidence + `</p>
            </div>
`
		}
	} else {
		html += `
            <p>No vulnerabilities found.</p>
`
	}

	// Close HTML
	html += `
        </div>
        
        <div class="footer">
            <p>Generated by aether Scanner v1.0.0</p>
            <p>Developer: ibrahimsql | <a href="https://github.com/ibrahimsql/aether">GitHub</a></p>
        </div>
    </div>
</body>
</html>
`

	// Write to file
	err := os.WriteFile(o.config.ReportPath, []byte(html), 0644)
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		return
	}

	fmt.Printf("Report saved to: %s\n", o.config.ReportPath)
}

// generateHAR generates a HAR file
func (o *Outputter) generateHAR(result *scanner.Result) {
	// Create HAR structure
	har := map[string]interface{}{
		"log": map[string]interface{}{
			"version": "1.2",
			"creator": map[string]string{
				"name":    "aether",
				"version": "1.0.0",
			},
			"browser": map[string]string{
				"name":    "aether",
				"version": "1.0.0",
			},
			"pages": []map[string]interface{}{
				{
					"startedDateTime": result.StartTime,
					"id":              "page_1",
					"title":           "aether Scan",
					"pageTimings": map[string]int{
						"onContentLoad": -1,
						"onLoad":        -1,
					},
				},
			},
			"entries": []map[string]interface{}{},
		},
	}

	// Add entries for each vulnerability
	entries := []map[string]interface{}{}
	for i, vuln := range result.Vulnerabilities {
		entry := map[string]interface{}{
			"pageref":         "page_1",
			"startedDateTime": result.StartTime,
			"time":            0,
			"request": map[string]interface{}{
				"method":      "GET",
				"url":         vuln.URL,
				"httpVersion": "HTTP/1.1",
				"cookies":     []interface{}{},
				"headers":     []interface{}{},
				"queryString": []interface{}{},
				"headersSize": -1,
				"bodySize":    -1,
			},
			"response": map[string]interface{}{
				"status":      200,
				"statusText":  "OK",
				"httpVersion": "HTTP/1.1",
				"cookies":     []interface{}{},
				"headers":     []interface{}{},
				"content": map[string]interface{}{
					"size":     0,
					"mimeType": "text/html",
					"text":     vuln.Evidence,
				},
				"redirectURL":   "",
				"headersSize":   -1,
				"bodySize":      -1,
				"_transferSize": 0,
				"_error":        nil,
			},
			"cache":              map[string]interface{}{},
			"timings":            map[string]int{"send": 0, "wait": 0, "receive": 0},
			"serverIPAddress":    "127.0.0.1",
			"_serverPort":        80,
			"_priority":          "High",
			"_resourceType":      "document",
			"_webSocketMessages": []interface{}{},
			"connection":         "0",
			"_initiator": map[string]interface{}{
				"type": "other",
			},
			"_frameId": "1",
			"_id":      fmt.Sprintf("%d", i+1),
		}

		entries = append(entries, entry)
	}

	// Add entries to HAR
	har["log"].(map[string]interface{})["entries"] = entries

	// Convert to JSON
	jsonData, err := json.MarshalIndent(har, "", "  ")
	if err != nil {
		fmt.Printf("Error generating HAR file: %v\n", err)
		return
	}

	// Write to file
	err = os.WriteFile(o.config.HARPath, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing HAR file: %v\n", err)
		return
	}

	fmt.Printf("HAR file saved to: %s\n", o.config.HARPath)
}
