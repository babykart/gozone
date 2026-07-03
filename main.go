// Command gozone is the PowerDNS Admin Interface.
//
// This file is intentionally minimal: it only wires the CLI entry point to
// the command tree defined under cmd/. All real work (server bootstrap,
// subcommands, HTTP wiring) lives in package cmd.
package main

import (
	"github.com/babykart/gozone/cmd"
	"github.com/babykart/gozone/internal/logger"
)

func main() {
	if err := cmd.Execute(); err != nil {
		logger.Fatal("gozone failed", "error", err)
	}
}
