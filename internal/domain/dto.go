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
