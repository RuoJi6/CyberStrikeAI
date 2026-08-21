package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"cyberstrike-ai/internal/egress"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "run":
			exitOnError(runConfigured(os.Args[2:]))
			return
		case "check":
			exitOnError(checkConfigured(os.Args[2:]))
			return
		default:
			log.Printf("unknown egress gateway command %q", os.Args[1])
			os.Exit(2)
		}
	}
	// Compatibility for stage-4 item-2 containers. They open no listener and
	// remain fail-closed until an explicit rebuild binds a snapshot.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := egress.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		exitOnError(err)
	}
}

func runConfigured(args []string) error {
	path, reference, err := parseSnapshotFlags("run", args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return egress.RunWithSnapshot(ctx, path, reference, os.Stdout)
}

func checkConfigured(args []string) error {
	path, reference, err := parseSnapshotFlags("check", args)
	if err != nil {
		return err
	}
	return egress.CheckSnapshot(path, reference, os.Stdout)
}

func parseSnapshotFlags(command string, args []string) (string, egress.SnapshotReference, error) {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	path := set.String("snapshot-path", "", "read-only boundary snapshot path")
	id := set.String("snapshot-id", "", "immutable boundary snapshot id")
	digest := set.String("snapshot-sha256", "", "expected boundary snapshot SHA-256")
	if err := set.Parse(args); err != nil {
		return "", egress.SnapshotReference{}, err
	}
	if set.NArg() != 0 || strings.TrimSpace(*path) == "" {
		return "", egress.SnapshotReference{}, fmt.Errorf("%s requires snapshot path, id and SHA-256", command)
	}
	return strings.TrimSpace(*path), egress.SnapshotReference{
		ID: strings.TrimSpace(*id), SHA256: strings.TrimSpace(*digest),
	}, nil
}

func exitOnError(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	log.Printf("egress gateway stopped: %v", err)
	os.Exit(1)
}
