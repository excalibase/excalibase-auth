package domain

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"fullName"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type ValidateRequest struct {
	Token string `json:"token"`
}

// TokenRequest is the OAuth2-shaped payload for the unified /token endpoint.
// Only the fields relevant to the chosen grant_type need to be populated.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Email        string `json:"email,omitempty"`
	Password     string `json:"password,omitempty"`
	APIKey       string `json:"api_key,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// CreateAPIKeyRequest is the body for POST /api-keys. The plaintext key
// returned in the response is only ever shown once.
type CreateAPIKeyRequest struct {
	Name    string `json:"name"`
	KeyType string `json:"keyType"` // "publishable" | "secret"
}

// CreateAPIKeyResponse contains the freshly-minted plaintext key (returned
// once and never readable again) plus the metadata that GET /api-keys exposes.
type CreateAPIKeyResponse struct {
	ID         int64  `json:"id"`
	Plaintext  string `json:"plaintext"`
	KeyPrefix  string `json:"keyPrefix"`
	KeyType    string `json:"keyType"`
	Name       string `json:"name"`
	CreatedAt  string `json:"createdAt"`
}

// APIKeyInfo is the read-only listing shape (no plaintext, no key_hash).
type APIKeyInfo struct {
	ID         int64   `json:"id"`
	KeyPrefix  string  `json:"keyPrefix"`
	KeyType    string  `json:"keyType"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
}

type AuthResponse struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	TokenType    string   `json:"tokenType"`
	ExpiresIn    int64    `json:"expiresIn"`
	User         UserInfo `json:"user"`
}

type UserInfo struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
}
