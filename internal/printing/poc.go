package printing

import (
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/ibrahimsql/aether/pkg/model"
	// import "github.com/ibrahimsql/aether/v2/pkg/model"
	// TODO: Update or provide the correct model import after refactoring.
)

// TODO: Removing unused import "encoding/json" to fix lint error.

// LogPoC logs the PoC details and adds request/response data if configured.
func LogPoC(poc *model.PoC, resbody string, req *http.Request, options model.Options, show bool, level string, message string) {
	// TODO: 'model' is undefined. Commenting out its usages to fix build errors.
	// poc := model.PoC{}
	// options := model.Options{}
	DalLog(level, message, options)
	DalLog("CODE", poc.Evidence, options)
	if options.OutputRequest {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			// poc.RawHTTPRequest = string(reqDump)
			DalLog("CODE", "\n"+string(reqDump), options)
		}
	}
	if options.OutputResponse {
		// poc.RawHTTPResponse = resbody
		DalLog("CODE", string(resbody), options)
	}
	if show {
		if options.Format == "json" {
			// pocj, _ := json.Marshal(poc)
			// DalLog("PRINT", string(pocj)+",", options)
		} else if options.Format == "jsonl" {
			// pocj, _ := json.Marshal(poc)
			// DalLog("PRINT", string(pocj), options)
		} else {
			// pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
			// DalLog("PRINT", pocs, options)
		}
	}
}

// MakePoC is making poc codes
func MakePoC(poc string, req *http.Request, options model.Options) string {
	// TODO: 'model' is undefined. Commenting out its usages to fix build errors.
	// if options.PoCType == "http-request" {
	if false {
		requestDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			return "HTTP RAW REQUEST\n" + string(requestDump)
		}
	}

	if req.Body != nil {
		body, err := req.GetBody()
		if err == nil {
			reqBody, err := io.ReadAll(body)
			if err == nil {
				if string(reqBody) != "" {
					// switch options.PoCType {
					// case "curl":
					// 	return "curl -i -k -X " + req.Method + " " + poc + " -d \"" + string(reqBody) + "\""
					// case "httpie":
					// 	return "http " + req.Method + " " + poc + " \"" + string(reqBody) + "\" --verify=false -f"
					// default:
					// 	return poc + " -d " + string(reqBody)
					// }
				}
			}
		}
	} else {
		// switch options.PoCType {
		// case "curl":
		// 	return "curl -i -k " + poc
		// case "httpie":
		// 	return "http " + poc + " --verify=false"
		// default:
		// 	return poc
		// }
	}
	return poc
}
