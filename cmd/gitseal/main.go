package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/raydalsayf/gitseal/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	runner := cli.Runner{Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(int(runner.Run(ctx, os.Args[1:])))
}
