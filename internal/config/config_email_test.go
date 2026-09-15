package config

import (
	"os"
	"testing"
)

func TestAudiencePrefix_Default(t *testing.T) {
	os.Unsetenv("AUTH_AUD_PREFIX")
	if got := Load().AudiencePrefix; got != "excalibase:" {
		t.Errorf("AudiencePrefix default: got %q, want %q", got, "excalibase:")
	}
}

func TestAudiencePrefix_EnvOverride(t *testing.T) {
	t.Setenv("AUTH_AUD_PREFIX", "tenant/")
	if got := Load().AudiencePrefix; got != "tenant/" {
		t.Errorf("AudiencePrefix: got %q, want %q", got, "tenant/")
	}
}

func TestSiteURL_DefaultsEmptyAndTrimsTrailingSlash(t *testing.T) {
	os.Unsetenv("AUTH_SITE_URL")
	if got := Load().SiteURL; got != "" {
		t.Errorf("SiteURL default: got %q, want empty", got)
	}

	t.Setenv("AUTH_SITE_URL", "https://app.example.com/")
	if got := Load().SiteURL; got != "https://app.example.com" {
		t.Errorf("SiteURL: got %q, want trailing slash trimmed", got)
	}
}
