package oauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/testutil/idpfake"
)

const callback = "https://api.test/auth/org/proj/callback/"

func client(provider string) oauth.Client {
	return oauth.Client{ID: idpfake.ClientID, Secret: idpfake.ClientSecret, RedirectURL: callback + provider}
}

func providers(fake *idpfake.IdP) map[string]oauth.Provider {
	return map[string]oauth.Provider{
		"google": oauth.Google(oauth.FakeGoogleEndpoints(fake.URL())),
		"github": oauth.GitHub(oauth.FakeGitHubEndpoints(fake.URL())),
	}
}

// signInAtFake walks the browser leg: the fake answers authorize with a code.
func signInAtFake(t *testing.T, provider oauth.Provider, flow oauth.Flow) string {
	t.Helper()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(provider.AuthCodeURL(client(provider.Name), flow))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %v", resp.StatusCode, err)
	}
	if location.Query().Get("state") != flow.State {
		t.Fatalf("state not echoed: %s", location)
	}
	return location.Query().Get("code")
}

func newFlow(t *testing.T) oauth.Flow {
	t.Helper()
	flow, err := oauth.NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func TestGoogleSignInChecksTheSignedIDTokenAndItsNonce(t *testing.T) {
	fake := idpfake.New(t)
	google := providers(fake)["google"]
	fake.SignInAs(idpfake.User{Subject: "g-1", Email: "ann@gmail.test", EmailVerified: true, Name: "Ann"})
	flow := newFlow(t)
	code := signInAtFake(t, google, flow)

	sent := fake.AuthorizeRequests()[0]
	if sent.Get("nonce") != flow.Nonce || sent.Get("redirect_uri") != callback+"google" || !strings.Contains(sent.Get("scope"), "openid") {
		t.Fatalf("authorize query = %v", sent)
	}
	identity, err := google.Identify(context.Background(), http.DefaultClient, client("google"), code, flow.Verifier, flow.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if identity != (oauth.Identity{Subject: "g-1", Email: "ann@gmail.test", Name: "Ann"}) {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestGoogleRefusesATamperedIDToken(t *testing.T) {
	for name, tamper := range map[string]idpfake.Tamper{
		"nonce": idpfake.TamperNonce, "audience": idpfake.TamperAudience,
		"signature": idpfake.TamperSignature, "issuer": idpfake.TamperIssuer,
	} {
		t.Run(name, func(t *testing.T) {
			fake := idpfake.New(t)
			google := providers(fake)["google"]
			fake.SignInAs(idpfake.User{Subject: "g-2", Email: "bob@gmail.test", EmailVerified: true})
			flow := newFlow(t)
			code := signInAtFake(t, google, flow)
			fake.TamperNext(tamper)
			if _, err := google.Identify(context.Background(), http.DefaultClient, client("google"), code, flow.Verifier, flow.Nonce); !errors.Is(err, oauth.ErrIDToken) {
				t.Fatalf("err = %v, want ErrIDToken", err)
			}
		})
	}
}

func TestAnAddressTheProviderDidNotVerifyIsRefused(t *testing.T) {
	for _, name := range []string{"google", "github"} {
		t.Run(name, func(t *testing.T) {
			fake := idpfake.New(t)
			provider := providers(fake)[name]
			fake.SignInAs(idpfake.User{Subject: "77", Email: "eve@test", EmailVerified: false})
			flow := newFlow(t)
			code := signInAtFake(t, provider, flow)
			if _, err := provider.Identify(context.Background(), http.DefaultClient, client(name), code, flow.Verifier, flow.Nonce); !errors.Is(err, oauth.ErrEmailNotVerified) {
				t.Fatalf("err = %v, want ErrEmailNotVerified", err)
			}
		})
	}
}

func TestGitHubSignInTakesThePrimaryVerifiedAddress(t *testing.T) {
	fake := idpfake.New(t)
	github := providers(fake)["github"]
	fake.SignInAs(idpfake.User{Subject: "4242", Email: "octo@github.test", EmailVerified: true, Name: "Octo"})
	flow := newFlow(t)
	code := signInAtFake(t, github, flow)
	if sent := fake.AuthorizeRequests()[0]; sent.Get("nonce") != "" || !strings.Contains(sent.Get("scope"), "user:email") {
		t.Fatalf("authorize query = %v", sent)
	}
	identity, err := github.Identify(context.Background(), http.DefaultClient, client("github"), code, flow.Verifier, flow.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if identity != (oauth.Identity{Subject: "4242", Email: "octo@github.test", Name: "Octo"}) {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestTheCodeExchangeNeedsTheVerifierAndTheSecret(t *testing.T) {
	fake := idpfake.New(t)
	github := providers(fake)["github"]
	fake.SignInAs(idpfake.User{Subject: "1", Email: "a@test", EmailVerified: true})
	flow := newFlow(t)
	code := signInAtFake(t, github, flow)
	other := newFlow(t)
	if _, err := github.Identify(context.Background(), http.DefaultClient, client("github"), code, other.Verifier, ""); !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("wrong verifier: %v", err)
	}
	flow = newFlow(t)
	code = signInAtFake(t, github, flow)
	wrongSecret := client("github")
	wrongSecret.Secret = "nope"
	if _, err := github.Identify(context.Background(), http.DefaultClient, wrongSecret, code, flow.Verifier, ""); !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestPKCEChallenge(t *testing.T) {
	// RFC 7636 appendix B.
	if got := oauth.S256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("S256 = %s", got)
	}
	if !oauth.VerifierMatches("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") {
		t.Fatal("matching verifier refused")
	}
	if oauth.VerifierMatches("short", oauth.S256("short")) {
		t.Fatal("a verifier under 43 characters was accepted")
	}
	for challenge, valid := range map[string]bool{
		"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM": true,
		"":                            false,
		"too-short":                   false,
		strings.Repeat("a", 129):      false,
		strings.Repeat("a", 42) + "=": false,
	} {
		if oauth.ValidChallenge(challenge) != valid {
			t.Errorf("ValidChallenge(%q) = %v", challenge, !valid)
		}
	}
}

func TestNewFlowIsRandom(t *testing.T) {
	first, second := newFlow(t), newFlow(t)
	if first.State == second.State || first.Verifier == second.Verifier || first.Nonce == second.Nonce || len(first.State) < 43 {
		t.Fatalf("flows = %+v %+v", first, second)
	}
}
