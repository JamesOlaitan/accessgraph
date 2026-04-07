// Package main is the entry point for the accessgraph CLI.
//
// It delegates all flag parsing and command dispatch to the commands package and
// maps any returned error to a non-zero exit code. os.Exit is called only here,
// never inside the commands package itself.
package main

import (
	"os"

	"github.com/JamesOlaitan/accessgraph/cmd/accessgraph/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
