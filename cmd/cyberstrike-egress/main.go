package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"cyberstrike-ai/internal/egress"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := egress.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("egress gateway stopped: %v", err)
		os.Exit(1)
	}
}
