package printing

import (
	// import "github.com/ibrahimsql/aether/v2/pkg/model"
	// TODO: Update or provide the correct model import after refactoring.
	"fmt"

	"github.com/ibrahimsql/aether/pkg/model"
)

// Banner
func Banner(options model.Options) {
	// TODO: 'model' is undefined. Commenting out its usages to fix build errors.
	// var m model.SomeType
	banner := `
    ___       __   __   ________  ________  ________  ________  
   |\  \     |\  \|\  \|\   __  \|\   __  \|\   __  \|\   ___  \ 
   \ \  \    \ \  \ \  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \\ \  \ 
 __ \ \  \  __\ \  \ \  \ \   __  \ \   ____\ \   __  \ \  \\ \  \ 
|\  \\_\  \|\__\_\  \ \  \ \  \ \  \ \  \___|\ \  \ \  \ \  \\ \  \ 
\ \________\|__|\__\ \__\ \__\ \__\ \__\    \ \__\ \__\ \__\\ \__\
 \|________|   \|__|\|__|\|__|\|__|\|__|     \|__|\|__|\|__| \|__|

aether - Advanced XSS Scanner
Author: ibrahimsql
Github: https://github.com/ibrahimsql/aether
Website: https://aether.ibrahimsql.com
Version: v2.0.0
`
	fmt.Println(banner)
}
