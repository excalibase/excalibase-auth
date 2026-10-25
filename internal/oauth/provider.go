// Package oauth signs end users in with Google or GitHub: authorization code
// with PKCE, an OIDC nonce checked in Google's signed id_token, and only an
// address the provider verified. Provider tokens are used once and dropped.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

var (
	ErrExchange         = errors.New("the provider refused the authorization code")
	ErrIDToken          = errors.New("the provider's id_token is not valid")
	ErrEmailNotVerified = errors.New("the provider has not verified this email address")
	ErrIdentity         = errors.New("the provider's account could not be read")
)

// Endpoints locates a provider; tests point them at a fake.
type Endpoints struct {
	AuthURL  string
	TokenURL string
	// APIBase serves GitHub's user and email reads.
	APIBase string
	// JWKSURL and Issuer check Google's id_token.
	JWKSURL string
	Issuer  string
}

var (
	GoogleEndpoints = Endpoints{
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
		Issuer:   "https://accounts.google.com",
	}
	GitHubEndpoints = Endpoints{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
		APIBase:  "https://api.github.com",
	}
)

// FakeGoogleEndpoints and FakeGitHubEndpoints are the routes of testutil/idpfake.
func FakeGoogleEndpoints(base string) Endpoints {
	return Endpoints{AuthURL: base + "/google/authorize", TokenURL: base + "/google/token", JWKSURL: base + "/google/certs", Issuer: base + "/google"}
}

func FakeGitHubEndpoints(base string) Endpoints {
	return Endpoints{AuthURL: base + "/github/login/oauth/authorize", TokenURL: base + "/github/login/oauth/access_token", APIBase: base + "/github/api"}
}

// Client is a project's own OAuth app at the provider.
type Client struct {
	ID          string
	Secret      string
	RedirectURL string
}

// Identity is a provider account with a provider-verified address.
type Identity struct {
	Subject string
	Email   string
	Name    string
}

type identifier func(ctx context.Context, httpClient *http.Client, token *oauth2.Token, client Client, nonce string) (Identity, error)

// Provider is one sign-in provider.
type Provider struct {
	Name      string
	endpoints Endpoints
	scopes    []string
	oidc      bool
	identify  identifier
}

func Google(endpoints Endpoints) Provider {
	keys := newKeySet(endpoints.JWKSURL)
	provider := Provider{Name: "google", endpoints: endpoints, scopes: []string{"openid", "email", "profile"}, oidc: true}
	provider.identify = func(ctx context.Context, httpClient *http.Client, token *oauth2.Token, client Client, nonce string) (Identity, error) {
		raw, _ := token.Extra("id_token").(string)
		return verifyIDToken(ctx, httpClient, keys, raw, endpoints.Issuer, client.ID, nonce)
	}
	return provider
}

func GitHub(endpoints Endpoints) Provider {
	provider := Provider{Name: "github", endpoints: endpoints, scopes: []string{"read:user", "user:email"}}
	provider.identify = func(ctx context.Context, httpClient *http.Client, token *oauth2.Token, _ Client, _ string) (Identity, error) {
		return identifyGitHub(ctx, httpClient, endpoints.APIBase, token.AccessToken)
	}
	return provider
}

func (p Provider) config(client Client) *oauth2.Config {
	return &oauth2.Config{
		ClientID: client.ID, ClientSecret: client.Secret, RedirectURL: client.RedirectURL, Scopes: p.scopes,
		Endpoint: oauth2.Endpoint{AuthURL: p.endpoints.AuthURL, TokenURL: p.endpoints.TokenURL},
	}
}

// AuthCodeURL is where the browser goes to sign in at the provider.
func (p Provider) AuthCodeURL(client Client, flow Flow) string {
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(flow.Verifier)}
	if p.oidc {
		options = append(options, oauth2.SetAuthURLParam("nonce", flow.Nonce))
	}
	return p.config(client).AuthCodeURL(flow.State, options...)
}

// Identify exchanges the code with our verifier and reads the verified identity.
func (p Provider) Identify(ctx context.Context, httpClient *http.Client, client Client, code, verifier, nonce string) (Identity, error) {
	token, err := p.config(client).Exchange(context.WithValue(ctx, oauth2.HTTPClient, httpClient), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %s", ErrExchange, exchangeReason(err))
	}
	return p.identify(ctx, httpClient, token, client, nonce)
}

// exchangeReason keeps the provider's error code and drops its free text.
func exchangeReason(err error) string {
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && retrieve.ErrorCode != "" {
		return retrieve.ErrorCode
	}
	return "token endpoint failed"
}

func identifyGitHub(ctx context.Context, httpClient *http.Client, apiBase, accessToken string) (Identity, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := getJSON(ctx, httpClient, apiBase+"/user", accessToken, &user); err != nil {
		return Identity{}, err
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, httpClient, apiBase+"/user/emails", accessToken, &emails); err != nil {
		return Identity{}, err
	}
	if user.ID <= 0 {
		return Identity{}, ErrIdentity
	}
	name := user.Name
	if name == "" {
		name = user.Login
	}
	for _, candidate := range emails {
		if candidate.Primary && candidate.Verified && candidate.Email != "" {
			return Identity{Subject: strconv.FormatInt(user.ID, 10), Email: candidate.Email, Name: name}, nil
		}
	}
	return Identity{}, ErrEmailNotVerified
}

// maxProviderBody bounds what a provider answer may make us read.
const maxProviderBody = 1 << 20

func getJSON(ctx context.Context, httpClient *http.Client, url, accessToken string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: unreachable", ErrIdentity)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrIdentity, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProviderBody)).Decode(out); err != nil {
		return fmt.Errorf("%w: malformed answer", ErrIdentity)
	}
	return nil
}
