package boundary

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var ErrInvalidTarget = errors.New("invalid boundary target")

type RequestTarget struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	Method string `json:"method"`
}

type RuleTarget struct {
	Host         string   `json:"host"`
	Schemes      []string `json:"schemes"`
	Ports        []int    `json:"ports"`
	PathPrefixes []string `json:"pathPrefixes"`
	Methods      []string `json:"methods"`
}

// NormalizeRequestTarget converts a URL and HTTP method into the canonical
// values consumed by the deterministic boundary matcher.
func NormalizeRequestTarget(rawURL, rawMethod string) (RequestTarget, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return RequestTarget{}, fmt.Errorf("%w: URL is required", ErrInvalidTarget)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return RequestTarget{}, fmt.Errorf("%w: parse URL: %v", ErrInvalidTarget, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" || parsed.Opaque != "" {
		return RequestTarget{}, fmt.Errorf("%w: absolute HTTP(S) URL is required", ErrInvalidTarget)
	}
	if parsed.User != nil {
		return RequestTarget{}, fmt.Errorf("%w: URL userinfo is not allowed", ErrInvalidTarget)
	}
	if parsed.Fragment != "" {
		return RequestTarget{}, fmt.Errorf("%w: URL fragments are not allowed", ErrInvalidTarget)
	}

	scheme, err := NormalizeScheme(parsed.Scheme)
	if err != nil {
		return RequestTarget{}, err
	}
	host, err := NormalizeHost(parsed.Hostname())
	if err != nil {
		return RequestTarget{}, err
	}
	port := 0
	if rawPort := parsed.Port(); rawPort != "" {
		port, err = strconv.Atoi(rawPort)
		if err != nil {
			return RequestTarget{}, fmt.Errorf("%w: invalid port %q", ErrInvalidTarget, rawPort)
		}
	}
	port, err = NormalizePort(scheme, port)
	if err != nil {
		return RequestTarget{}, err
	}
	normalizedPath, err := NormalizePath(parsed.EscapedPath())
	if err != nil {
		return RequestTarget{}, err
	}
	method, err := NormalizeMethod(rawMethod)
	if err != nil {
		return RequestTarget{}, err
	}
	return RequestTarget{Scheme: scheme, Host: host, Port: port, Path: normalizedPath, Method: method}, nil
}

// NormalizeRuleTarget canonicalizes every target dimension independently. It
// deliberately does not add policy defaults or make an allow/deny decision.
func NormalizeRuleTarget(input RuleTarget) (RuleTarget, error) {
	host, err := NormalizeHost(input.Host)
	if err != nil {
		return RuleTarget{}, err
	}
	schemes := make([]string, 0, len(input.Schemes))
	for _, raw := range input.Schemes {
		value, err := NormalizeScheme(raw)
		if err != nil {
			return RuleTarget{}, err
		}
		schemes = append(schemes, value)
	}
	ports := make([]int, 0, len(input.Ports))
	for _, value := range input.Ports {
		if value < 1 || value > 65535 {
			return RuleTarget{}, fmt.Errorf("%w: port %d is outside 1..65535", ErrInvalidTarget, value)
		}
		ports = append(ports, value)
	}
	paths := make([]string, 0, len(input.PathPrefixes))
	for _, raw := range input.PathPrefixes {
		if strings.TrimSpace(raw) == "" {
			return RuleTarget{}, fmt.Errorf("%w: rule path prefix must not be empty", ErrInvalidTarget)
		}
		value, err := NormalizePath(raw)
		if err != nil {
			return RuleTarget{}, err
		}
		paths = append(paths, value)
	}
	methods := make([]string, 0, len(input.Methods))
	for _, raw := range input.Methods {
		if strings.TrimSpace(raw) == "" {
			return RuleTarget{}, fmt.Errorf("%w: rule method must not be empty", ErrInvalidTarget)
		}
		value, err := NormalizeMethod(raw)
		if err != nil {
			return RuleTarget{}, err
		}
		methods = append(methods, value)
	}
	return RuleTarget{
		Host:         host,
		Schemes:      sortedUniqueStrings(schemes),
		Ports:        sortedUniqueInts(ports),
		PathPrefixes: sortedUniqueStrings(paths),
		Methods:      sortedUniqueStrings(methods),
	}, nil
}

func NormalizeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: host is required", ErrInvalidTarget)
	}
	bracketed := strings.HasPrefix(raw, "[") || strings.HasSuffix(raw, "]")
	if bracketed {
		if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
			return "", fmt.Errorf("%w: malformed bracketed host %q", ErrInvalidTarget, raw)
		}
		raw = raw[1 : len(raw)-1]
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		if bracketed && addr.Is4() {
			return "", fmt.Errorf("%w: brackets are only valid for IPv6 hosts", ErrInvalidTarget)
		}
		if addr.Zone() != "" {
			return "", fmt.Errorf("%w: scoped IP addresses are not allowed", ErrInvalidTarget)
		}
		return addr.Unmap().String(), nil
	}
	if bracketed {
		return "", fmt.Errorf("%w: brackets require a valid IPv6 host", ErrInvalidTarget)
	}
	if strings.Contains(raw, ":") {
		return "", fmt.Errorf("%w: host must not include a port", ErrInvalidTarget)
	}
	if looksLikeAmbiguousNumericHost(raw) {
		return "", fmt.Errorf("%w: ambiguous numeric host %q", ErrInvalidTarget, raw)
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid IDNA host %q: %v", ErrInvalidTarget, raw, err)
	}
	ascii = strings.ToLower(ascii)
	if strings.HasSuffix(ascii, ".") {
		ascii = strings.TrimSuffix(ascii, ".")
	}
	if addr, err := netip.ParseAddr(ascii); err == nil {
		return addr.Unmap().String(), nil
	}
	if looksLikeAmbiguousNumericHost(ascii) {
		return "", fmt.Errorf("%w: ambiguous numeric host %q", ErrInvalidTarget, raw)
	}
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", fmt.Errorf("%w: invalid host length", ErrInvalidTarget)
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: invalid DNS label in %q", ErrInvalidTarget, raw)
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", fmt.Errorf("%w: invalid DNS label in %q", ErrInvalidTarget, raw)
			}
		}
	}
	return ascii, nil
}

func NormalizeScheme(raw string) (string, error) {
	scheme := strings.ToLower(strings.TrimSpace(raw))
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%w: unsupported scheme %q", ErrInvalidTarget, raw)
	}
	return scheme, nil
}

// NormalizePort applies the HTTP(S) default when port is zero.
func NormalizePort(scheme string, port int) (int, error) {
	canonicalScheme, err := NormalizeScheme(scheme)
	if err != nil {
		return 0, err
	}
	if port == 0 {
		if canonicalScheme == "https" {
			return 443, nil
		}
		return 80, nil
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: port %d is outside 1..65535", ErrInvalidTarget, port)
	}
	return port, nil
}

func NormalizeMethod(raw string) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(raw))
	if method == "" {
		method = "GET"
	}
	for i := 0; i < len(method); i++ {
		if !isHTTPTokenByte(method[i]) {
			return "", fmt.Errorf("%w: invalid HTTP method %q", ErrInvalidTarget, raw)
		}
	}
	return method, nil
}

func NormalizePath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("%w: path must start with /", ErrInvalidTarget)
	}
	if strings.ContainsAny(raw, "?#") {
		return "", fmt.Errorf("%w: query or fragment must not be part of path", ErrInvalidTarget)
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid path escape: %v", ErrInvalidTarget, err)
	}
	if !utf8.ValidString(decoded) {
		return "", fmt.Errorf("%w: path is not valid UTF-8", ErrInvalidTarget)
	}
	for _, ch := range decoded {
		if ch == '\\' || ch < 0x20 || ch == 0x7f {
			return "", fmt.Errorf("%w: path contains an unsafe character", ErrInvalidTarget)
		}
	}
	if containsNestedEscape(decoded) {
		return "", fmt.Errorf("%w: path contains an ambiguous nested escape", ErrInvalidTarget)
	}
	preserveTrailingSlash := strings.HasSuffix(decoded, "/") || strings.HasSuffix(decoded, "/.") || strings.HasSuffix(decoded, "/..")
	canonical := path.Clean(decoded)
	if !strings.HasPrefix(canonical, "/") {
		canonical = "/" + canonical
	}
	if preserveTrailingSlash && canonical != "/" {
		canonical += "/"
	}
	return canonical, nil
}

func looksLikeAmbiguousNumericHost(host string) bool {
	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "0x") {
		for _, ch := range lower[2:] {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && ch != '.' {
				return false
			}
		}
		return true
	}
	for _, ch := range lower {
		if (ch < '0' || ch > '9') && ch != '.' {
			return false
		}
	}
	return true
}

func containsNestedEscape(value string) bool {
	for i := 0; i+2 < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		_, okHigh := fromHex(value[i+1])
		_, okLow := fromHex(value[i+2])
		if !okHigh || !okLow {
			continue
		}
		return true
	}
	return false
}

func fromHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func isHTTPTokenByte(value byte) bool {
	if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func sortedUniqueInts(values []int) []int {
	if len(values) == 0 {
		return []int{}
	}
	sort.Ints(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
