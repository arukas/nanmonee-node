// Command nanmonee-node-updater performs one panel-driven agent upgrade and
// exits.
//
// It is meant to be run by a root timer on the VPS, never by the node agent: the
// agent must not be able to replace its own binary. Each invocation asks the
// panel what this host should run, and does nothing when the answer is "noop".
package main

import (
	"flag"
	"log"
	"os"

	"nanmonee/node/internal/updater"
)

func main() {
	configPath := flag.String("config", "/etc/nanmonee-node/updater.json", "path to the owner-only updater config")
	flag.Parse()

	logger := log.New(os.Stdout, "updater: ", log.LstdFlags|log.LUTC)

	// The timer runs as root; refuse to start otherwise rather than fail halfway
	// through replacing a symlink.
	if os.Geteuid() != 0 {
		logger.Fatal("the updater must run as root")
	}
	config, err := updater.Load(*configPath)
	if err != nil {
		logger.Fatal(err)
	}
	client, err := updater.NewClient(config)
	if err != nil {
		logger.Fatal(err)
	}

	runner := updater.NewRunner(client, config)
	runner.Log = logger

	result, err := runner.Run()
	if err != nil {
		logger.Printf("check failed: %v", err)
		os.Exit(1)
	}
	if result == nil {
		return
	}
	if err := runner.Report(result); err != nil {
		logger.Printf("report failed: %v", err)
		// The upgrade outcome is already committed on disk. Exiting non-zero makes
		// the timer's failure visible in the journal; the next cycle re-reports
		// because the panel keeps the request outstanding.
		os.Exit(1)
	}
	if result.Outcome != "succeeded" {
		os.Exit(1)
	}
}
