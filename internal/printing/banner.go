package printing

import (
	"github.com/ibrahimsql/aether/v2/pkg/model"
	"fmt"
)

// Banner
func Banner(options model.Options) {
	banner := `
    ___       __   __   ________  ________  ________  ________  
   |\  \     |\  \|\  \|\   __  \|\   __  \|\   __  \|\   ___  \ 
   \ \  \    \ \  \ \  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \\ \  \ 
 __ \ \  \  __\ \  \ \  \ \   __  \ \   ____\ \   __  \ \  \\ \  \ 
|\  \\_\  \|\__\_\  \ \  \ \  \ \  \ \  \___|\ \  \ \  \ \  \\ \  \ 
\ \________\|__|\__\ \__\ \__\ \__\ \__\    \ \__\ \__\ \__\\ \__\
 \|________|   \|__|\|__|\|__|\|__|\|__|     \|__|\|__|\|__| \|__|

Aether - Advanced XSS Scanner
Author: ibrahimsql
Github: https://github.com/ibrahimsql/aether
Website: https://aether.ibrahimsql.com
Version: v2.0.0
`
	fmt.Println(banner)
}
