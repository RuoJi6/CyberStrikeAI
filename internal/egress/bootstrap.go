// Package egress implements the fail-closed per-conversation egress gateway.
// Protocol forwarding is intentionally introduced in later stage-4 items; the
// bootstrap process only provides a hardened, lifecycle-managed sidecar.
package egress

import (
	"context"
	"errors"
)

// Run keeps the bootstrap gateway alive until its container is stopped. It
// opens no listener and forwards no traffic, so this stage cannot accidentally
// create an unreviewed network path before policy loading is implemented.
func Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("egress gateway context is required")
	}
	<-ctx.Done()
	return nil
}
