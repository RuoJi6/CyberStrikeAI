package egress

import "testing"

func TestParseUpstreamProtocol(t *testing.T) {
	for _, raw := range []string{"http", "HTTPS", " socks5 "} {
		if _, err := ParseUpstreamProtocol(raw); err != nil {
			t.Fatalf("ParseUpstreamProtocol(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{"", "socks", "socks4", "ftp", "http://"} {
		if _, err := ParseUpstreamProtocol(raw); err == nil {
			t.Fatalf("ParseUpstreamProtocol(%q) succeeded", raw)
		}
	}
}

func TestNormalizeUpstreamHost(t *testing.T) {
	tests := map[string]string{
		"Proxy.Example.COM.": "proxy.example.com",
		"[2001:db8::1]":      "2001:db8::1",
		"127.0.0.1":          "127.0.0.1",
		"测试.example":         "xn--0zwm56d.example",
	}
	for raw, want := range tests {
		got, err := NormalizeUpstreamHost(raw)
		if err != nil || got != want {
			t.Fatalf("NormalizeUpstreamHost(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "http://proxy.example", "user@proxy.example", "proxy.example:8080", "*.example", "a..b", "[fe80::1%en0]"} {
		if got, err := NormalizeUpstreamHost(raw); err == nil {
			t.Fatalf("NormalizeUpstreamHost(%q) = %q, want error", raw, got)
		}
	}
}
