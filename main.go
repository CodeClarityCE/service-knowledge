package main

import (
	"flag"
	"os"
	"time"

	knowledge "github.com/CodeClarityCE/service-knowledge/src"
)

func main() {
	var help = flag.Bool("help", false, "Show help")
	var know = flag.Bool("knowledge", false, "Use knowledge component")
	var action = ""

	// Bind flags
	flag.StringVar(&action, "action", action, "Action to perform")

	// Parse flags
	flag.Parse()

	// Show help
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *know {
		switch action {
		case "setup":
			knowledge.Setup(true)
		case "update":
			knowledge.Update()
		default:
			flag.Usage()
			os.Exit(0)
		}
	} else {
		flag.Usage()
		for {
			knowledge.Setup(false)
			// knowledge.Update()
			time.Sleep(1 * time.Hour)
		}
		// os.Exit(0)
	}
}
