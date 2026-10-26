package pgstore

import (
	"context"
	"errors"

	"github.com/excalibase/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

func (s *Store) SignInWithIdentity(ctx context.Context, claim store.IdentityClaim, allowCreate bool) (store.Account, store.IdentityOutcome, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Account{}, 0, err
	}
	defer tx.Rollback(ctx)

	userID, outcome, err := resolveIdentity(ctx, tx, claim, allowCreate)
	if err != nil {
		return store.Account{}, 0, err
	}
	account, err := scanAccount(tx.QueryRow(ctx, "SELECT "+accountColumns+" FROM auth.users WHERE id = $1", userID))
	if err != nil {
		return store.Account{}, 0, err
	}
	return account, outcome, tx.Commit(ctx)
}

// resolveIdentity applies the linking rule: a known identity wins; otherwise
// an account with the address is linked when verified and taken over when not.
func resolveIdentity(ctx context.Context, tx pgx.Tx, claim store.IdentityClaim, allowCreate bool) (int64, store.IdentityOutcome, error) {
	var userID int64
	err := tx.QueryRow(ctx,
		`UPDATE auth.identities SET email = $3, email_verified = true, last_sign_in_at = NOW()
		 WHERE provider = $1 AND subject = $2 RETURNING user_id`,
		claim.Provider, claim.Subject, claim.Email).Scan(&userID)
	if err == nil {
		return userID, store.IdentityKnown, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, err
	}

	userID, verified, err := accountForAddress(ctx, tx, claim.Email)
	outcome := store.IdentityLinked
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if !allowCreate {
			return 0, 0, store.ErrSignupsDisabled
		}
		if userID, err = createProviderUser(ctx, tx, claim); err != nil {
			return 0, 0, err
		}
		outcome = store.IdentityCreated
	case err != nil:
		return 0, 0, err
	case !verified:
		if userID, err = takeOver(ctx, tx, userID, claim); err != nil {
			return 0, 0, err
		}
		outcome = store.IdentityTookOver
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO auth.identities (user_id, provider, subject, email, email_verified, last_sign_in_at)
		 VALUES ($1, $2, $3, $4, true, NOW())`,
		userID, claim.Provider, claim.Subject, claim.Email)
	return userID, outcome, err
}

// accountForAddress finds the account a provider address reaches: the exact
// address, else the only one matching it whatever its case. A disabled one is
// refused, so it is neither signed in to nor taken over.
func accountForAddress(ctx context.Context, tx pgx.Tx, email string) (int64, bool, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, email = $1, email_verified AND email_verified_at IS NOT NULL, enabled FROM auth.users
		 WHERE lower(email) = lower($1) ORDER BY email = $1 DESC, id LIMIT 2 FOR UPDATE`, email)
	if err != nil {
		return 0, false, err
	}
	matches, err := pgx.CollectRows(rows, pgx.RowToStructByPos[store.AddressMatch])
	if err != nil {
		return 0, false, err
	}
	match, err := store.PickAddressMatch(matches, pgx.ErrNoRows)
	if err == nil && !match.Enabled {
		err = store.ErrAccountDisabled
	}
	return match.ID, match.Verified, err
}

func createProviderUser(ctx context.Context, tx pgx.Tx, claim store.IdentityClaim) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO auth.users (email, password, full_name, role, enabled, email_verified, email_verified_at, created_at, updated_at)
		 VALUES ($1, NULL, $2, 'user', true, true, NOW(), NOW(), NOW()) RETURNING id`,
		claim.Email, claim.FullName).Scan(&id)
	return id, err
}

// takeOver replaces an account whose address nobody proved with a new one for
// the provider-verified owner. A new id means nothing issued to the old
// account, an access token included, reaches the owner's; the old account's
// sessions, links and keys go with it.
func takeOver(ctx context.Context, tx pgx.Tx, userID int64, claim store.IdentityClaim) (int64, error) {
	if _, err := tx.Exec(ctx, "DELETE FROM auth.users WHERE id = $1", userID); err != nil {
		return 0, err
	}
	return createProviderUser(ctx, tx, claim)
}

func (s *Store) SaveFlowState(ctx context.Context, state store.FlowState) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM auth.flow_states WHERE expires_at < NOW()"); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth.flow_states (state_hash, provider, idp_code_verifier, nonce, client_code_challenge, redirect_to, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		state.StateHash, state.Provider, state.IDPCodeVerifier, state.Nonce, state.ClientCodeChallenge, state.RedirectTo, state.ExpiresAt)
	return err
}

func (s *Store) ConsumeFlowState(ctx context.Context, stateHash string) (store.FlowState, error) {
	state := store.FlowState{StateHash: stateHash}
	err := s.pool.QueryRow(ctx,
		`DELETE FROM auth.flow_states WHERE state_hash = $1 AND expires_at > NOW()
		 RETURNING provider, idp_code_verifier, nonce, client_code_challenge, redirect_to, expires_at`,
		stateHash).Scan(&state.Provider, &state.IDPCodeVerifier, &state.Nonce, &state.ClientCodeChallenge, &state.RedirectTo, &state.ExpiresAt)
	return state, notFound(err)
}

func (s *Store) SaveAuthCode(ctx context.Context, code store.AuthCode) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM auth.auth_codes WHERE expires_at < NOW()"); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		"INSERT INTO auth.auth_codes (code_hash, user_id, code_challenge, expires_at) VALUES ($1, $2, $3, $4)",
		code.CodeHash, code.UserID, code.CodeChallenge, code.ExpiresAt)
	return err
}

func (s *Store) RedeemAuthCode(ctx context.Context, codeHash string) (store.AuthCode, error) {
	code := store.AuthCode{CodeHash: codeHash}
	err := s.pool.QueryRow(ctx,
		`UPDATE auth.auth_codes SET consumed_at = NOW()
		 WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
		 RETURNING user_id, code_challenge, expires_at`,
		codeHash).Scan(&code.UserID, &code.CodeChallenge, &code.ExpiresAt)
	return code, notFound(err)
}
