package auth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Sub       string `json:"sub"`
	UserID    int64  `json:"userId"`
	ProjectID string `json:"projectId"`
	Role      string `json:"role"`
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
		"sub":       claims.Sub,
		"userId":    claims.UserID,
		"projectId": claims.ProjectID,
		"role":      claims.Role,
		"iss":       s.issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(s.expSeconds) * time.Second).Unix(),
	})

	return token.SignedString(s.privateKey)
}

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
	return &Claims{
		Sub:       mapClaims["sub"].(string),
		UserID:    int64(userID),
		ProjectID: mapClaims["projectId"].(string),
		Role:      mapClaims["role"].(string),
	}, nil
}
