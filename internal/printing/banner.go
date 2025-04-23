package printing

import (
	"fmt"
	"github.com/ibrahimsql/aether/pkg/model"
)

// Banner prints the application banner
func Banner(options model.Options) {
	banner := `

	________                 _____ ______   ________  ________      
	|\   ____\               |\   _ \  _   \|\   __  \|\   ___  \    
	\ \  \___|   ____________\ \  \\\__\ \  \ \  \|\  \ \  \\ \  \   
	 \ \  \  ___|\____________\ \  \\|__| \  \ \   __  \ \  \\ \  \  
	  \ \  \|\  \|____________|\ \  \    \ \  \ \  \ \  \ \  \\ \  \ 
	   \ \_______\              \ \__\    \ \__\ \__\ \__\ \__\\ \__\
		\|_______|               \|__|     \|__|\|__|\|__|\|__| \|__|
	
Aether - Advanced XSS Scanner
Author: ibrahimsql
Github: https://github.com/ibrahimsql/aether
Website: https://aether.ibrahimsql.github.io
Version: v2.0.0
`
	fmt.Println(banner)
}
