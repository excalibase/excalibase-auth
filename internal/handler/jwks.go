package handler

import (
	"encoding/json"
	"log"
	"net/http"
)

// JWKS serves the public half of the token-signing key; it carries no
// private material and needs no credential.
func (h *AuthHandler) JWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(h.jwtService.PublicKeyJWKS()); err != nil {
		log.Printf("write jwks: %v", err)
	}
}
