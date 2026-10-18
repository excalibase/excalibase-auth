package pool

import (
	"context"

	"github.com/excalibase/auth/internal/store/pgstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// getPool is GetStore for tests that read a Postgres project's pool directly.
func getPool(mgr *Manager, ctx context.Context, orgSlug, projectID string) (*pgxpool.Pool, error) {
	opened, err := mgr.GetStore(ctx, orgSlug, projectID)
	if err != nil {
		return nil, err
	}
	return opened.(*pgstore.Store).Pool(), nil
}
