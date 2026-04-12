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

type Claims struct {
	Sub         string `json:"sub"`
	UserID      int64  `json:"userId"`
	ProjectID   string `json:"projectId"`   // "{orgSlug}/{projectName}" composite key
	OrgSlug     string `json:"orgSlug"`
	ProjectName string `json:"projectName"`
	Role        string `json:"role"`
}

type JWTService struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
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
		expSeconds: expSeconds,
	}, nil
}

func (s *JWTService) Sign(claims Claims) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":         claims.Sub,
		"userId":      claims.UserID,
		"projectId":   claims.ProjectID,
		"orgSlug":     claims.OrgSlug,
		"projectName": claims.ProjectName,
		"role":        claims.Role,
		"iss":         s.issuer,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Duration(s.expSeconds) * time.Second).Unix(),
	})

	return token.SignedString(s.privateKey)
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

func (s *JWTService) Verify(tokenString string) (*Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	userID, _ := mapClaims["userId"].(float64)
	orgSlug, _ := mapClaims["orgSlug"].(string)
	projectName, _ := mapClaims["projectName"].(string)
	return &Claims{
		Sub:         mapClaims["sub"].(string),
		UserID:      int64(userID),
		ProjectID:   mapClaims["projectId"].(string),
		OrgSlug:     orgSlug,
		ProjectName: projectName,
		Role:        mapClaims["role"].(string),
	}, nil
}
