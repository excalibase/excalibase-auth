package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWK represents a single JSON Web Key for an EC public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// DefaultAudiencePrefix is prepended to the projectId to form the `aud` entry
// every token carries. Overridable via AUTH_AUD_PREFIX so a deployment can
// namespace its audiences without a code change.
const DefaultAudiencePrefix = "excalibase:"

// Token use values carried in the `token_use` claim. Resource servers accept
// only TokenUseAccess on API calls, so a refresh credential can never be
// replayed as an access token.
const (
	TokenUseAccess  = "access"
	TokenUseRefresh = "refresh"
)

type Claims struct {
	Sub         string `json:"sub"`
	UserID      int64  `json:"userId"`
	ProjectID   string `json:"projectId"` // opaque project ref minted by provisioning (e.g. "proj_a3k9fx7b2k")
	OrgSlug     string `json:"orgSlug"`
	ProjectName string `json:"projectName"` // display name (user-typed, e.g. "blog")
	OrgName     string `json:"orgName"`     // display name (e.g. "Acme Corp")
	Role        string `json:"role"`
	// Scope distinguishes credential origin: "authenticated" (password login),
	// "public" (publishable api key, browser-safe), or "service" (secret api key,
	// server-side only). Empty for legacy password flows that don't set it.
	Scope string `json:"scope,omitempty"`
	// KeyID points back to auth.api_keys.id when this token was minted via an
	// api-key grant. Zero for password / refresh grants.
	KeyID int64 `json:"keyId,omitempty"`
	// Audience is the `aud` claim, always emitted as an array holding a single
	// project-scoped entry ("<prefix><projectId>"). Populated by Sign from
	// ProjectID; read back by Verify.
	Audience []string `json:"aud"`
	// TokenUse separates access credentials from refresh credentials.
	TokenUse string `json:"token_use"`
	// EmailVerified mirrors auth.users.email_verified so resource servers can
	// gate on it without a round trip to the auth service.
	EmailVerified bool `json:"email_verified"`
}

type JWTService struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
	audPrefix  string
	expSeconds int
}

func NewJWTService(privateKeyPEM string, issuer string, expSeconds int) (*JWTService, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &JWTService{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
		issuer:     issuer,
		audPrefix:  DefaultAudiencePrefix,
		expSeconds: expSeconds,
	}, nil
}

// SetAudiencePrefix overrides the prefix used to build the `aud` claim. An
// empty prefix is ignored so a blank AUTH_AUD_PREFIX can never mint tokens
// whose audience is a bare projectId.
func (s *JWTService) SetAudiencePrefix(prefix string) {
	if prefix != "" {
		s.audPrefix = prefix
	}
}

// AudienceFor returns the `aud` entry a token for projectID must carry.
func (s *JWTService) AudienceFor(projectID string) string {
	return s.audPrefix + projectID
}

func (s *JWTService) Sign(claims Claims) (string, error) {
	now := time.Now()
	mc := jwt.MapClaims{
		"sub":         claims.Sub,
		"userId":      claims.UserID,
		"projectId":   claims.ProjectID,
		"orgSlug":     claims.OrgSlug,
		"projectName": claims.ProjectName,
		"orgName":     claims.OrgName,
		"role":        claims.Role,
		"iss":         s.issuer,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Duration(s.expSeconds) * time.Second).Unix(),
		// Array form so verifiers that expect the multi-valued `aud` shape
		// (RFC 7519 §4.1.3) need no special-casing.
		"aud":            []string{s.AudienceFor(claims.ProjectID)},
		"token_use":      TokenUseAccess,
		"email_verified": claims.EmailVerified,
	}
	// Optional claims — only emit when set so password-flow tokens stay
	// byte-for-byte identical to the pre-api-key behavior.
	if claims.Scope != "" {
		mc["scope"] = claims.Scope
	}
	if claims.KeyID != 0 {
		mc["keyId"] = claims.KeyID
	}
	return jwt.NewWithClaims(jwt.SigningMethodES256, mc).SignedString(s.privateKey)
}

// PublicKeyJWKS returns the JWKS representation of the EC public key.
func (s *JWTService) PublicKeyJWKS() JWKS {
	pub := s.publicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := padBytes(pub.X.Bytes(), byteLen)
	y := padBytes(pub.Y.Bytes(), byteLen)

	crv := "P-256"
	if pub.Curve == elliptic.P384() {
		crv = "P-384"
	} else if pub.Curve == elliptic.P521() {
		crv = "P-521"
	}

	return JWKS{
		Keys: []JWK{
			{
				Kty: "EC",
				Crv: crv,
				X:   base64.RawURLEncoding.EncodeToString(x),
				Y:   base64.RawURLEncoding.EncodeToString(y),
				Use: "sig",
				Alg: "ES256",
				Kid: "excalibase-auth-key",
			},
		},
	}
}

func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// ensure big is used (imported for padBytes via math/big)
var _ = (*big.Int)(nil)

// audienceClaim normalises the `aud` claim, which RFC 7519 permits as either a
// single string or an array of strings, into a slice.
func audienceClaim(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (s *JWTService) Verify(tokenString string) (*Claims, error) {
	// Pin ES256 explicitly via WithValidMethods — a bare *SigningMethodECDSA check
	// would also accept ES384/ES512, and this closes any alg-confusion ambiguity.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Issuer binding. Only enforced when an issuer is configured so deployments
	// that never set one keep their existing behavior. When configured, reject
	// any token whose `iss` claim doesn't match the service's issuer — this stops
	// tokens minted by a different issuer from being accepted here.
	if s.issuer != "" {
		iss, _ := mapClaims["iss"].(string)
		if iss != s.issuer {
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	userID, _ := mapClaims["userId"].(float64)
	orgSlug, _ := mapClaims["orgSlug"].(string)
	projectName, _ := mapClaims["projectName"].(string)
	orgName, _ := mapClaims["orgName"].(string)
	sub, _ := mapClaims["sub"].(string)
	projectID, _ := mapClaims["projectId"].(string)
	role, _ := mapClaims["role"].(string)
	scope, _ := mapClaims["scope"].(string)
	keyID, _ := mapClaims["keyId"].(float64)
	tokenUse, _ := mapClaims["token_use"].(string)
	emailVerified, _ := mapClaims["email_verified"].(bool)
	return &Claims{
		Audience:      audienceClaim(mapClaims["aud"]),
		TokenUse:      tokenUse,
		EmailVerified: emailVerified,
		Sub:           sub,
		UserID:        int64(userID),
		ProjectID:     projectID,
		OrgSlug:       orgSlug,
		ProjectName:   projectName,
		OrgName:       orgName,
		Role:          role,
		Scope:         scope,
		KeyID:         int64(keyID),
	}, nil
}
