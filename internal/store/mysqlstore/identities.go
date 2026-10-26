package mysqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/excalibase/auth/internal/store"
)

func (s *Store) SignInWithIdentity(ctx context.Context, claim store.IdentityClaim, allowCreate bool) (store.Account, store.IdentityOutcome, error) {
	var (
		account store.Account
		outcome store.IdentityOutcome
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		userID, resolved, err := resolveIdentity(ctx, tx, claim, allowCreate)
		if err != nil {
			return err
		}
		outcome = resolved
		account, err = scanAccount(tx.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM users WHERE id = ?", userID))
		return err
	})
	if err != nil {
		return store.Account{}, 0, err
	}
	return account, outcome, nil
}

// resolveIdentity applies the linking rule: a known identity wins; otherwise
// an account with the address is linked when verified and taken over when not.
func resolveIdentity(ctx context.Context, tx *sql.Tx, claim store.IdentityClaim, allowCreate bool) (int64, store.IdentityOutcome, error) {
	var userID int64
	err := tx.QueryRowContext(ctx,
		"SELECT user_id FROM identities WHERE provider = ? AND subject = ? FOR UPDATE",
		claim.Provider, claim.Subject).Scan(&userID)
	if err == nil {
		_, err = tx.ExecContext(ctx,
			"UPDATE identities SET email = ?, email_verified = TRUE, last_sign_in_at = NOW(6) WHERE provider = ? AND subject = ?",
			claim.Email, claim.Provider, claim.Subject)
		return userID, store.IdentityKnown, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, 0, err
	}

	userID, verified, err := accountForAddress(ctx, tx, claim.Email)
	outcome := store.IdentityLinked
	switch {
	case errors.Is(err, sql.ErrNoRows):
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
	_, err = tx.ExecContext(ctx,
		`INSERT INTO identities (user_id, provider, subject, email, email_verified, last_sign_in_at)
		 VALUES (?, ?, ?, ?, TRUE, NOW(6))`,
		userID, claim.Provider, claim.Subject, claim.Email)
	return userID, outcome, err
}

// accountForAddress finds the account a provider address reaches, refusing a
// disabled one; see pgstore.
func accountForAddress(ctx context.Context, tx *sql.Tx, email string) (int64, bool, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, email = ?, email_verified AND email_verified_at IS NOT NULL, enabled FROM users
		 WHERE LOWER(email) = LOWER(?) ORDER BY email = ? DESC, id LIMIT 2 FOR UPDATE`, email, email, email)
	if err != nil {
		return 0, false, err
	}
	defer rows.Close()
	var matches []store.AddressMatch
	for rows.Next() {
		var match store.AddressMatch
		if err := rows.Scan(&match.ID, &match.Exact, &match.Verified, &match.Enabled); err != nil {
			return 0, false, err
		}
		matches = append(matches, match)
	}
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	match, err := store.PickAddressMatch(matches, sql.ErrNoRows)
	if err == nil && !match.Enabled {
		err = store.ErrAccountDisabled
	}
	return match.ID, match.Verified, err
}

func createProviderUser(ctx context.Context, tx *sql.Tx, claim store.IdentityClaim) (int64, error) {
	result, err := tx.ExecContext(ctx,
		`INSERT INTO users (email, password, full_name, role, enabled, email_verified, email_verified_at, created_at, updated_at)
		 VALUES (?, NULL, ?, 'user', TRUE, TRUE, NOW(6), NOW(6), NOW(6))`,
		claim.Email, claim.FullName)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// takeOver replaces an account whose address nobody proved with a new one for
// the provider-verified owner; see pgstore.
func takeOver(ctx context.Context, tx *sql.Tx, userID int64, claim store.IdentityClaim) (int64, error) {
	if _, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID); err != nil {
		return 0, err
	}
	return createProviderUser(ctx, tx, claim)
}

func (s *Store) SaveFlowState(ctx context.Context, state store.FlowState) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM flow_states WHERE expires_at < NOW(6)"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO flow_states (state_hash, provider, idp_code_verifier, nonce, client_code_challenge, redirect_to, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		state.StateHash, state.Provider, state.IDPCodeVerifier, state.Nonce, state.ClientCodeChallenge, state.RedirectTo, state.ExpiresAt.UTC())
	return err
}

// ConsumeFlowState reads and deletes under a row lock, so of two callbacks
// with one state exactly one gets it.
func (s *Store) ConsumeFlowState(ctx context.Context, stateHash string) (store.FlowState, error) {
	state := store.FlowState{StateHash: stateHash}
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT provider, idp_code_verifier, nonce, client_code_challenge, redirect_to, expires_at
			 FROM flow_states WHERE state_hash = ? AND expires_at > NOW(6) FOR UPDATE`, stateHash,
		).Scan(&state.Provider, &state.IDPCodeVerifier, &state.Nonce, &state.ClientCodeChallenge, &state.RedirectTo, &state.ExpiresAt); err != nil {
			return notFound(err)
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM flow_states WHERE state_hash = ?", stateHash)
		return err
	})
	if err != nil {
		return store.FlowState{}, err
	}
	return state, nil
}

func (s *Store) SaveAuthCode(ctx context.Context, code store.AuthCode) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM auth_codes WHERE expires_at < NOW(6)"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO auth_codes (code_hash, user_id, code_challenge, expires_at) VALUES (?, ?, ?, ?)",
		code.CodeHash, code.UserID, code.CodeChallenge, code.ExpiresAt.UTC())
	return err
}

func (s *Store) RedeemAuthCode(ctx context.Context, codeHash string) (store.AuthCode, error) {
	code := store.AuthCode{CodeHash: codeHash}
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT user_id, code_challenge, expires_at FROM auth_codes
			 WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > NOW(6) FOR UPDATE`, codeHash,
		).Scan(&code.UserID, &code.CodeChallenge, &code.ExpiresAt); err != nil {
			return notFound(err)
		}
		_, err := tx.ExecContext(ctx, "UPDATE auth_codes SET consumed_at = NOW(6) WHERE code_hash = ?", codeHash)
		return err
	})
	if err != nil {
		return store.AuthCode{}, err
	}
	return code, nil
}
