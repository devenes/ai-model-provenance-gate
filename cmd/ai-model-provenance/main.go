// Command ai-model-provenance is the CLI entrypoint for AI Model Provenance Gate.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/devenes/ai-model-provenance-gate/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
