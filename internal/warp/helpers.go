package warp

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var errBadEndpointKey = errors.New("endpoint public key is not a valid ECDSA key")

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeBase64(s string) ([]byte, error) {
	// Tolerate raw/base64url variants used across registration responses.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func pemDecode(b []byte) (*pem.Block, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	return block, nil
}

var teamRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// NormalizeTeam accepts a bare subdomain ("mycompany"), a full team hostname
// ("mycompany.cloudflareaccess.com") or a URL containing either, and returns
// the bare team subdomain.
func NormalizeTeam(input string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" {
		return "", errors.New("team subdomain is required")
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Host
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/warp")
	s = strings.TrimSuffix(s, ".cloudflareaccess.com")
	s = strings.TrimSpace(s)
	if !teamRe.MatchString(s) {
		return "", errors.New("invalid team subdomain (expected letters, digits and hyphens)")
	}
	return s, nil
}

// EnrollmentURL is the page the user must open and sign in to; its success
// screen contains the device token warpalt needs.
func EnrollmentURL(team string) string {
	return "https://" + team + ".cloudflareaccess.com/warp"
}

// ParseTeamToken extracts the enrollment token from whatever the user pasted:
// a bare token, the com.cloudflare.warp://... success URL, or an https URL
// carrying a token query parameter.
func ParseTeamToken(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("enrollment token is required")
	}
	if strings.Contains(s, "token=") {
		if u, err := url.Parse(s); err == nil {
			if t := u.Query().Get("token"); t != "" {
				return t, nil
			}
		}
		// Non-URL forms such as com.cloudflare.warp://host/auth?token=...
		if i := strings.Index(s, "token="); i >= 0 {
			t := s[i+len("token="):]
			if j := strings.IndexAny(t, "& \t\"'"); j >= 0 {
				t = t[:j]
			}
			if t != "" {
				return t, nil
			}
		}
	}
	return s, nil
}

// OpenBrowser opens url in the user's default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// endpointHost strips the port/bracket decorations from a registration
// endpoint value ("162.159.x.y:0", "[2606:...]:0") leaving a bare IP/host.
func endpointHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(host, "[]")
	}
	if net.ParseIP(strings.Trim(raw, "[]")) != nil {
		return strings.Trim(raw, "[]")
	}
	if i := strings.LastIndex(raw, ":"); i > 0 {
		if _, err := strconv.Atoi(raw[i+1:]); err == nil {
			return strings.Trim(raw[:i], "[]")
		}
	}
	return strings.Trim(raw, "[]")
}

func defaultDeviceName() string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "warpalt-device"
}
