package handler

import (
	"context"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/store"
)

// noticeLinked tells the account's own proven address that a way to sign in
// was added to it, so its owner learns of a link they did not make. An
// unproven address is never mailed: it may not be the owner's.
func (h *AuthHandler) noticeLinked(ctx context.Context, db store.Store, projectID string, userID int64, method, linkedEmail string) {
	account, err := db.AccountByID(ctx, userID)
	if err != nil || !account.EmailVerified || account.Email == "" {
		return
	}
	msg := email.Message{ProjectID: projectID, To: account.Email, Template: email.TemplateIdentityLinked,
		Data: map[string]string{"userEmail": account.Email, "method": method, "linkedEmail": linkedEmail}}
	h.dispatchMail(func() { h.sendOTPMail(projectID, msg) })
}
