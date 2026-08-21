// Package egress implements the fail-closed per-conversation egress gateway.
package egress

import (
	"context"
	"errors"
)

// Run keeps legacy stage-4 item-2 bootstrap containers alive until stopped. It
// opens no listener and forwards no traffic. Snapshot-aware containers use
// RunWithSnapshot and the policy-enforcing proxy instead.
func Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("egress gateway context is required")
	}
	<-ctx.Done()
	return nil
}
