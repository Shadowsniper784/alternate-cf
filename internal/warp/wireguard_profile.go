package warp

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

var ErrInvalidArgs = errors.New("invalid arguments")

// WgProfileData holds the data needed to generate a WireGuard profile.
type WgProfileData struct {
	PrivateKey string
	Address1   string
	Address2   string
	PublicKey  string
	Endpoint   string
	Keepalive  int
	ListenPort int
	DNS        string
}

var (
	profileMu sync.Mutex
	profiles  = make(map[string]*WgProfileData)
)

// SaveWgProfile stores a WireGuard profile for a device.
func SaveWgProfile(deviceID string, data *WgProfileData) {
	profileMu.Lock()
	defer profileMu.Unlock()
	profiles[deviceID] = data
}

// LoadWgProfile retrieves a WireGuard profile by device ID.
func LoadWgProfile(deviceID string) *WgProfileData {
	profileMu.Lock()
	defer profileMu.Unlock()
	return profiles[deviceID]
}

// DeleteWgProfile removes a WireGuard profile.
func DeleteWgProfile(deviceID string) {
	profileMu.Lock()
	defer profileMu.Unlock()
	delete(profiles, deviceID)
}

// ListWgProfiles returns all stored WireGuard profiles.
func ListWgProfiles() []*WgProfileData {
	profileMu.Lock()
	defer profileMu.Unlock()
	result := make([]*WgProfileData, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, p)
	}
	return result
}

// MarshalWgProfile converts a WgProfileData to wireguard-go format config.
func MarshalWgProfile(data *WgProfileData) ([]byte, error) {
	if data == nil {
		return nil, ErrInvalidArgs
	}
	s := &bytes.Buffer{}
	t, err := wgProfileTmpl()
	if err != nil {
		return nil, err
	}
	if err := t.Execute(s, data); err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// wgProfileTmpl parses the shared WireGuard profile template.
func wgProfileTmpl() (*template.Template, error) {
	return template.New("wgprofile").Parse(`[Interface]
PrivateKey = {{ .PrivateKey }}
Address = {{ .Address1 }}{{ if .Address2 }}
Address = {{ .Address2 }}{{ end }}
{{ if .ListenPort }}ListenPort = {{ .ListenPort }}{{ end }}
{{ if .DNS }}DNS = {{ .DNS }}{{ end }}

[Peer]
PublicKey = {{ .PublicKey }}
Endpoint = {{ .Endpoint }}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = {{ .Keepalive }}
`)
}

// WriteWgProfileFile writes a WireGuard profile to a file.
func WriteWgProfileFile(deviceID string, data *WgProfileData, path string) error {
	if data == nil {
		return ErrInvalidArgs
	}
	b, err := MarshalWgProfile(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// ReadWgProfileFile reads a WireGuard profile from a file.
func ReadWgProfileFile(path string) (*WgProfileData, error) {
	return ParseWgProfile(path)
}

// ParseWgProfile parses a standard WireGuard .conf file into profile data.
func ParseWgProfile(path string) (*WgProfileData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := &WgProfileData{}
	var addresses []string
	inPeer := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inPeer = strings.EqualFold(strings.Trim(line, "[]"), "peer")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "privatekey":
			if !inPeer {
				data.PrivateKey = value
			}
		case "address":
			addresses = append(addresses, strings.Split(value, ",")...)
		case "dns":
			data.DNS = strings.Split(value, ",")[0]
		case "listenport":
			data.ListenPort, _ = strconv.Atoi(value)
		case "publickey":
			if inPeer {
				data.PublicKey = value
			}
		case "endpoint":
			data.Endpoint = value
		case "persistentkeepalive":
			data.Keepalive, _ = strconv.Atoi(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(addresses) > 0 {
		data.Address1 = strings.TrimSpace(addresses[0])
	}
	if len(addresses) > 1 {
		data.Address2 = strings.TrimSpace(addresses[1])
	}
	if data.PrivateKey == "" || data.PublicKey == "" || data.Endpoint == "" {
		return nil, errors.New("wireguard config missing PrivateKey, PublicKey or Endpoint")
	}
	return data, nil
}

// GenerateWgProfile generates a WireGuard config string from the profile data.
func GenerateWgProfile(data *WgProfileData) (string, error) {
	if data == nil {
		return "", ErrInvalidArgs
	}
	s := &strings.Builder{}
	t, err := wgProfileTmpl()
	if err != nil {
		return "", err
	}
	if err := t.Execute(s, data); err != nil {
		return "", err
	}
	return s.String(), nil
}

// WgProfilePath returns the default path for a device's WireGuard profile.
func WgProfilePath(deviceID string) string {
	return filepath.Join(os.Getenv("HOME"), ".config", "warpalt", "wireguard", deviceID+".conf")
}
