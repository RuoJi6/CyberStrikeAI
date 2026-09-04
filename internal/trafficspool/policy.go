package trafficspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	AggregationPolicyVersion  = "traffic-aggregation/v1"
	AggregationPolicyFilename = ".aggregation-policy.json"
)

type AggregationPolicy struct {
	Version   string    `json:"version"`
	Mode      string    `json:"mode"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func validAggregationMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case AggregationModeAll, AggregationModeTools, AggregationModeNone:
		return true
	default:
		return false
	}
}

func (d *Directory) WriteAggregationPolicy(conversationID, mode string) error {
	if !validAggregationMode(mode) {
		return errors.New("traffic aggregation policy mode is invalid")
	}
	path, err := d.ConversationPath(conversationID)
	if err != nil {
		return err
	}
	content, err := json.Marshal(AggregationPolicy{
		Version: AggregationPolicyVersion, Mode: strings.ToLower(strings.TrimSpace(mode)), UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(path, ".aggregation-policy-*.tmp")
	if err != nil {
		return fmt.Errorf("create aggregation policy temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(path, AggregationPolicyFilename)); err != nil {
		return fmt.Errorf("publish aggregation policy: %w", err)
	}
	cleanup = false
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open aggregation policy directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync aggregation policy directory: %w", err)
	}
	return nil
}

func loadAggregationPolicy(root string) string {
	content, err := os.ReadFile(filepath.Join(root, AggregationPolicyFilename))
	if err != nil {
		return AggregationModeNone
	}
	var policy AggregationPolicy
	if json.Unmarshal(content, &policy) != nil || policy.Version != AggregationPolicyVersion || !validAggregationMode(policy.Mode) {
		return AggregationModeNone
	}
	return strings.ToLower(strings.TrimSpace(policy.Mode))
}

// WatchAggregationPolicy hot-applies an atomically published policy. Missing,
// malformed and unknown policies fail to no aggregation so evidence is kept.
func WatchAggregationPolicy(ctx context.Context, root string, sink *CompactingSink) error {
	if ctx == nil || sink == nil {
		return errors.New("aggregation policy watcher is not configured")
	}
	apply := func() error { return sink.SetAggregationMode(context.Background(), loadAggregationPolicy(root)) }
	if err := apply(); err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := apply(); err != nil {
				return err
			}
		}
	}
}
