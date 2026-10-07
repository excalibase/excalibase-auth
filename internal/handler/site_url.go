package handler

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

const siteURLRequiredCode = "site_url_required"

// siteURLRequiredMessage is what the developer sees; it names the fix.
const siteURLRequiredMessage = "this project has no site URL, so auth cannot build a link for the email: " +
	"set the site URL in the project's auth settings (an absolute https URL, or http://localhost for development)"

// normalizeSiteURL returns the base for email links, or "" when raw cannot
// safely be one: it must be an absolute https URL (http only for localhost),
// with a host and no credentials, query or fragment. A trailing slash is dropped.
func normalizeSiteURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return ""
		}
	default:
		return ""
	}
	return strings.TrimRight(parsed.String(), "/")
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// writeSiteURLRequired answers 422 with a code the caller can switch on, and
// logs the cause for the operator. It depends on the project's configuration
// only, never on an account, so it reveals nothing about who is registered.
func writeSiteURLRequired(w http.ResponseWriter, projectID string) {
	log.Printf("auth.site_url.missing project=%s: refusing to send an email without an absolute link", safeLog(projectID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	writeJSON(w, map[string]interface{}{
		"error":  siteURLRequiredMessage,
		"code":   siteURLRequiredCode,
		"status": http.StatusUnprocessableEntity,
	})
}
