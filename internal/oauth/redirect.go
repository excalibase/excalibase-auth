package oauth

import (
	"net/url"
	"strings"
)

// AllowedRedirect reports whether raw is one of the allowed URLs: scheme, host,
// port and path must match exactly; only the query may differ. It returns raw
// as it will be redirected to.
func AllowedRedirect(raw string, allowed []string) (string, bool) {
	if raw != strings.TrimSpace(raw) {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	target, ok := comparableForm(raw)
	if !ok {
		return "", false
	}
	for _, entry := range allowed {
		if candidate, ok := comparableForm(entry); ok && candidate == target {
			return parsed.String(), true
		}
	}
	return "", false
}

// comparableForm is the scheme, host, port and path of an absolute http(s) URL with
// no userinfo or fragment, lower-cased where the URL is case-insensitive.
func comparableForm(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	if !plainPath(parsed) || strings.Contains(parsed.Host, "*") {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" && port != defaultPort(scheme) {
		host += ":" + port
	}
	path := parsed.EscapedPath()
	if path == "/" {
		path = ""
	}
	return scheme + "://" + host + path, true
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// WithParam sets one query parameter on a URL that already passed AllowedRedirect.
func WithParam(raw, key, value string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// WithError reports a failed sign-in to the app: an error code and no code.
func WithError(raw, code string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	query := parsed.Query()
	query.Del("code")
	query.Set("error", code)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// plainPath refuses dot segments, encoded slashes and control characters,
// which a browser or server may read differently from the stored entry.
func plainPath(parsed *url.URL) bool {
	for _, r := range parsed.Path {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return !strings.Contains(strings.ToLower(parsed.EscapedPath()), "%2f")
}
