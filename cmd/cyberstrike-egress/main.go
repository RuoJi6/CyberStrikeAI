package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/trafficspool"
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
	path, reference, routePath, routeReference, authPath, authReference, tlsCertPath, tlsKeyPath, tlsReference, err := parseGatewayFlags("run", args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	recoveries := make(chan struct{}, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				select {
				case recoveries <- struct{}{}:
				default:
				}
			}
		}
	}()
	trafficLimits, err := trafficLimitsFromEnvironment()
	if err != nil {
		return err
	}
	trafficSink, conversationID, closeTrafficSink, err := trafficSinkFromEnvironment()
	if err != nil {
		return err
	}
	runErr := egress.RunWithSnapshot(ctx, path, reference, os.Stdout, egress.GatewayOptions{
		UpstreamRoutePath: routePath, UpstreamRoute: routeReference,
		AuthProfilesPath: authPath, AuthProfiles: authReference,
		TLSCertificatePath: tlsCertPath, TLSPrivateKeyPath: tlsKeyPath, TLSAuthority: tlsReference,
		ManualRecovery: recoveries,
		TrafficLimits:  trafficLimits,
		Proxy: egress.ProxyOptions{
			TrafficSink: trafficSink, ConversationID: conversationID,
			RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		},
	})
	if closeTrafficSink != nil {
		return errors.Join(runErr, closeTrafficSink())
	}
	return runErr
}

func checkConfigured(args []string) error {
	path, reference, routePath, routeReference, authPath, authReference, tlsCertPath, tlsKeyPath, tlsReference, err := parseGatewayFlags("check", args)
	if err != nil {
		return err
	}
	trafficLimits, err := trafficLimitsFromEnvironment()
	if err != nil {
		return err
	}
	if err := validateTrafficSpoolEnvironment(); err != nil {
		return err
	}
	return egress.CheckGatewayWithOptions(path, reference, egress.GatewayOptions{
		UpstreamRoutePath: routePath, UpstreamRoute: routeReference,
		AuthProfilesPath: authPath, AuthProfiles: authReference,
		TLSCertificatePath: tlsCertPath, TLSPrivateKeyPath: tlsKeyPath, TLSAuthority: tlsReference,
		TrafficLimits: trafficLimits,
	}, os.Stdout)
}

func validateTrafficSpoolEnvironment() error {
	path := strings.TrimSpace(os.Getenv("CYBERSTRIKE_TRAFFIC_SPOOL_PATH"))
	conversationID := strings.TrimSpace(os.Getenv("CYBERSTRIKE_CONVERSATION_ID"))
	if (path == "") != (conversationID == "") {
		return fmt.Errorf("CYBERSTRIKE_TRAFFIC_SPOOL_PATH and CYBERSTRIKE_CONVERSATION_ID must be configured together")
	}
	return nil
}

func trafficSinkFromEnvironment() (egress.TrafficSink, string, func() error, error) {
	if err := validateTrafficSpoolEnvironment(); err != nil {
		return nil, "", nil, err
	}
	path := strings.TrimSpace(os.Getenv("CYBERSTRIKE_TRAFFIC_SPOOL_PATH"))
	conversationID := strings.TrimSpace(os.Getenv("CYBERSTRIKE_CONVERSATION_ID"))
	if path == "" {
		return nil, "", nil, nil
	}
	writer, err := trafficspool.NewWriter(path, conversationID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("configure traffic spool: %w", err)
	}
	compactor, err := trafficspool.NewCompactingSink(writer.Write, trafficspool.DefaultCompactConfig())
	if err != nil {
		return nil, "", nil, fmt.Errorf("configure traffic compactor: %w", err)
	}
	return compactor.Write, conversationID, compactor.Close, nil
}

func trafficLimitsFromEnvironment() (*egress.TrafficLimits, error) {
	names := []string{"CYBERSTRIKE_HTTP_RPS", "CYBERSTRIKE_TCP_CPS", "CYBERSTRIKE_UDP_DPS"}
	values := make([]int, len(names))
	configured := false
	for index, name := range names {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		configured = true
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("%s must be a non-negative integer", name)
		}
		values[index] = value
	}
	if !configured {
		return nil, nil
	}
	limits := &egress.TrafficLimits{
		HTTPRequestsPerSecond: values[0], TCPConnectionsPerSecond: values[1], UDPDatagramsPerSecond: values[2],
	}
	if err := egress.ValidateTrafficLimits(limits); err != nil {
		return nil, err
	}
	return limits, nil
}

func parseGatewayFlags(command string, args []string) (string, egress.SnapshotReference, string, *egress.UpstreamRouteReference, string, *egress.AuthProfilesReference, string, string, *egress.TLSAuthorityReference, error) {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	path := set.String("snapshot-path", "", "read-only boundary snapshot path")
	id := set.String("snapshot-id", "", "immutable boundary snapshot id")
	digest := set.String("snapshot-sha256", "", "expected boundary snapshot SHA-256")
	routePath := set.String("upstream-route-path", "", "read-only upstream route path")
	routeID := set.String("upstream-route-id", "", "immutable upstream route id")
	routeDigest := set.String("upstream-route-sha256", "", "expected upstream route SHA-256")
	authPath := set.String("auth-profiles-path", "", "read-only auth profiles path")
	authID := set.String("auth-profiles-id", "", "immutable auth profiles id")
	authDigest := set.String("auth-profiles-sha256", "", "expected auth profiles SHA-256")
	tlsCertPath := set.String("tls-ca-cert-path", "", "read-only conversation TLS CA certificate path")
	tlsKeyPath := set.String("tls-ca-key-path", "", "gateway-only conversation TLS CA private key path")
	tlsID := set.String("tls-ca-id", "", "conversation TLS authority id")
	tlsCertDigest := set.String("tls-ca-cert-sha256", "", "expected TLS CA certificate SHA-256")
	tlsKeyDigest := set.String("tls-ca-key-sha256", "", "expected TLS CA private key SHA-256")
	if err := set.Parse(args); err != nil {
		return "", egress.SnapshotReference{}, "", nil, "", nil, "", "", nil, err
	}
	if set.NArg() != 0 || strings.TrimSpace(*path) == "" {
		return "", egress.SnapshotReference{}, "", nil, "", nil, "", "", nil, fmt.Errorf("%s requires snapshot path, id and SHA-256", command)
	}
	reference := egress.SnapshotReference{ID: strings.TrimSpace(*id), SHA256: strings.TrimSpace(*digest)}
	routeConfigured := strings.TrimSpace(*routePath) != "" || strings.TrimSpace(*routeID) != "" || strings.TrimSpace(*routeDigest) != ""
	if routeConfigured && (strings.TrimSpace(*routePath) == "" || strings.TrimSpace(*routeID) == "" || strings.TrimSpace(*routeDigest) == "") {
		return "", egress.SnapshotReference{}, "", nil, "", nil, "", "", nil, fmt.Errorf("%s requires all upstream route flags together", command)
	}
	var routeReference *egress.UpstreamRouteReference
	if routeConfigured {
		routeReference = &egress.UpstreamRouteReference{ID: strings.TrimSpace(*routeID), SHA256: strings.TrimSpace(*routeDigest)}
	}
	authConfigured := strings.TrimSpace(*authPath) != "" || strings.TrimSpace(*authID) != "" || strings.TrimSpace(*authDigest) != ""
	if authConfigured && (strings.TrimSpace(*authPath) == "" || strings.TrimSpace(*authID) == "" || strings.TrimSpace(*authDigest) == "") {
		return "", egress.SnapshotReference{}, "", nil, "", nil, "", "", nil, fmt.Errorf("%s requires all auth profiles flags together", command)
	}
	var authReference *egress.AuthProfilesReference
	if authConfigured {
		authReference = &egress.AuthProfilesReference{ID: strings.TrimSpace(*authID), SHA256: strings.TrimSpace(*authDigest)}
	}
	tlsConfigured := strings.TrimSpace(*tlsCertPath) != "" || strings.TrimSpace(*tlsKeyPath) != "" || strings.TrimSpace(*tlsID) != "" || strings.TrimSpace(*tlsCertDigest) != "" || strings.TrimSpace(*tlsKeyDigest) != ""
	if tlsConfigured && (strings.TrimSpace(*tlsCertPath) == "" || strings.TrimSpace(*tlsKeyPath) == "" || strings.TrimSpace(*tlsID) == "" || strings.TrimSpace(*tlsCertDigest) == "" || strings.TrimSpace(*tlsKeyDigest) == "") {
		return "", egress.SnapshotReference{}, "", nil, "", nil, "", "", nil, fmt.Errorf("%s requires all TLS authority flags together", command)
	}
	var tlsReference *egress.TLSAuthorityReference
	if tlsConfigured {
		tlsReference = &egress.TLSAuthorityReference{ID: strings.TrimSpace(*tlsID), CertificateSHA256: strings.TrimSpace(*tlsCertDigest), PrivateKeySHA256: strings.TrimSpace(*tlsKeyDigest)}
	}
	return strings.TrimSpace(*path), reference, strings.TrimSpace(*routePath), routeReference,
		strings.TrimSpace(*authPath), authReference, strings.TrimSpace(*tlsCertPath), strings.TrimSpace(*tlsKeyPath), tlsReference, nil
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
