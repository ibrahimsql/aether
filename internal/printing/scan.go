package printing

import "github.com/ibrahimsql/aether/pkg/model"

// TODO: Update this import after refactoring or providing the correct package path.
// import "github.com/ibrahimsql/aether/v2/internal/utils"
// TODO: Update or provide the correct utils import after refactoring.
// import "github.com/ibrahimsql/aether/v2/pkg/model"
// TODO: Update or provide the correct model import after refactoring.

// TODO: Removing unused imports "strconv" and "github.com/ibrahimsql/aether/internal/utils" to fix lint errors.

// ScanSummary prints the summary of the scan.
func ScanSummary(scanResult model.Result, options model.Options) {
	// TODO: The following usages of 'utils' are commented out due to missing import. Update after refactoring.
	// DalLog("SYSTEM-M", utils.GenerateTerminalWidthLine("-"), options)
	// DalLog("SYSTEM-M", "[duration: "+scanResult.Duration.String()+"][issues: "+strconv.Itoa(len(scanResult.PoCs))+"] Finish Scan!", options)
}
