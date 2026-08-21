package egress

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

type UpstreamProtocol string

const (
	UpstreamProtocolHTTP   UpstreamProtocol = "http"
	UpstreamProtocolHTTPS  UpstreamProtocol = "https"
	UpstreamProtocolSOCKS5 UpstreamProtocol = "socks5"
)

func ParseUpstreamProtocol(raw string) (UpstreamProtocol, error) {
	protocol := UpstreamProtocol(strings.ToLower(strings.TrimSpace(raw)))
	switch protocol {
	case UpstreamProtocolHTTP, UpstreamProtocolHTTPS, UpstreamProtocolSOCKS5:
		return protocol, nil
	default:
		return "", fmt.Errorf("unsupported egress proxy protocol %q", strings.TrimSpace(raw))
	}
}

// NormalizeUpstreamHost accepts one literal IP or DNS hostname without a URL,
// port, path, userinfo, wildcard, or IPv6 zone. Private and link-local
// addresses are deliberately allowed here because the documented test and
// deployment topology can place the upstream proxy on the VM default gateway.
func NormalizeUpstreamHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", fmt.Errorf("egress proxy host is required")
	}
	if !utf8.ValidString(host) || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t /?#@\\") {
		return "", fmt.Errorf("egress proxy host must be a hostname or IP address without URL components")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSpace(host[1 : len(host)-1])
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", fmt.Errorf("egress proxy host must not contain an IPv6 zone")
		}
		return address.Unmap().String(), nil
	}
	if strings.Contains(host, ":") || strings.HasPrefix(host, ".") || strings.Contains(host, "..") || strings.Contains(host, "*") {
		return "", fmt.Errorf("egress proxy host is invalid")
	}
	canonical, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(host), "."))
	if err != nil || canonical == "" || len(canonical) > 253 {
		return "", fmt.Errorf("egress proxy host is invalid")
	}
	for _, label := range strings.Split(canonical, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("egress proxy host is invalid")
		}
	}
	return canonical, nil
}

func ValidateUpstreamName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("egress proxy name is required")
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 120 || strings.ContainsAny(name, "\x00\r\n") {
		return "", fmt.Errorf("egress proxy name must contain at most 120 valid characters")
	}
	return name, nil
}

func ValidateUpstreamPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("egress proxy port must be between 1 and 65535")
	}
	return nil
}
