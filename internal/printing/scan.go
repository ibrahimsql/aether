package printing

import (
	"strconv"

	"github.com/ibrahimsql/aetherxss/v2/internal/utils"
	"github.com/ibrahimsql/aetherxss/v2/pkg/model"
)

// ScanSummary prints the summary of the scan.
func ScanSummary(scanResult model.Result, options model.Options) {
	DalLog("SYSTEM-M", utils.GenerateTerminalWidthLine("-"), options)
	DalLog("SYSTEM-M", "[duration: "+scanResult.Duration.String()+"][issues: "+strconv.Itoa(len(scanResult.PoCs))+"] Finish Scan!", options)
}
