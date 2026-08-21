package boundary

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeHostCanonicalizesIDNAAndIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: " ExAmPle.COM. ", want: "example.com"},
		{input: "例子.测试", want: "xn--fsqu00a.xn--0zwm56d"},
		{input: "bücher.example", want: "xn--bcher-kva.example"},
		{input: "192.0.2.1", want: "192.0.2.1"},
		{input: "１９２．０．２．１", want: "192.0.2.1"},
		{input: "[2001:0db8:0:0:0:0:0:1]", want: "2001:db8::1"},
		{input: "::ffff:192.0.2.1", want: "192.0.2.1"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizeHost(test.input)
			if err != nil || got != test.want {
				t.Fatalf("NormalizeHost(%q) = %q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestNormalizeHostRejectsAmbiguousOrMalformedInput(t *testing.T) {
	for _, input := range []string{
		"", "127.1", "2130706433", "0177.0.0.1", "0x7f000001",
		"192.168.001.001", "[192.0.2.1]", "[example.com]", "fe80::1%eth0", "[2001:db8::1", "example.com:443",
		"１２７．１",
		"*.example.com", "bad_label.example", "-edge.example", "example..com",
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := NormalizeHost(input); !errors.Is(err, ErrInvalidTarget) || got != "" {
				t.Fatalf("NormalizeHost(%q) = %q, %v", input, got, err)
			}
		})
	}
}

func TestNormalizeRequestTargetCanonicalizesEveryDimension(t *testing.T) {
	got, err := NormalizeRequestTarget(" HTTPS://BÜCHER.example:443/a/%2e%2e/b//c/?q=1 ", " post ")
	if err != nil {
		t.Fatal(err)
	}
	want := RequestTarget{
		Scheme: "https",
		Host:   "xn--bcher-kva.example",
		Port:   443,
		Path:   "/b/c/",
		Method: "POST",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("target = %#v; want %#v", got, want)
	}

	got, err = NormalizeRequestTarget("http://example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 80 || got.Path != "/" || got.Method != "GET" {
		t.Fatalf("default target = %#v", got)
	}

	got, err = NormalizeRequestTarget("https://[2001:db8::1]:8443/v1", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "2001:db8::1" || got.Port != 8443 {
		t.Fatalf("IPv6 target = %#v", got)
	}
}

func TestNormalizeRequestTargetRejectsAmbiguousURLs(t *testing.T) {
	for _, raw := range []string{
		"", "/relative", "ftp://example.com/a", "https://user@example.com/a",
		"https://example.com:99999/a", "https://example.com/a#fragment",
		"https://127.1/a", "https://[fe80::1%25eth0]/a",
	} {
		t.Run(raw, func(t *testing.T) {
			if got, err := NormalizeRequestTarget(raw, "GET"); !errors.Is(err, ErrInvalidTarget) || got != (RequestTarget{}) {
				t.Fatalf("NormalizeRequestTarget(%q) = %#v, %v", raw, got, err)
			}
		})
	}
}

func TestNormalizePathRemovesEncodedDotSegmentsAndPreservesPrefixBoundary(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: "/"},
		{input: "/a/%2e%2e/b//c", want: "/b/c"},
		{input: "/v1/%2E/records/", want: "/v1/records/"},
		{input: "/a%2fb", want: "/a/b"},
		{input: "/caf%C3%A9", want: "/café"},
		{input: "//v1///items/..", want: "/v1/"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizePath(test.input)
			if err != nil || got != test.want {
				t.Fatalf("NormalizePath(%q) = %q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestNormalizePathRejectsParserDifferentials(t *testing.T) {
	for _, input := range []string{
		"relative", "/bad%escape", "/a\\b", "/a%5cb", "/a%00b", "/a?query",
		"/a#fragment", "/a/%252e%252e/b", "/a/%252f/b", "/a/%255c/b", "/a/%2541/b",
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := NormalizePath(input); !errors.Is(err, ErrInvalidTarget) || got != "" {
				t.Fatalf("NormalizePath(%q) = %q, %v", input, got, err)
			}
		})
	}
}

func TestNormalizeRuleTargetSortsAndDeduplicatesCanonicalValues(t *testing.T) {
	got, err := NormalizeRuleTarget(RuleTarget{
		Host:         " BÜCHER.example. ",
		Schemes:      []string{"HTTPS", "http", "https"},
		Ports:        []int{443, 80, 443},
		PathPrefixes: []string{"/v1//", "/v1/%2e/", "/"},
		Methods:      []string{"post", "GET", "POST"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := RuleTarget{
		Host:         "xn--bcher-kva.example",
		Schemes:      []string{"http", "https"},
		Ports:        []int{80, 443},
		PathPrefixes: []string{"/", "/v1/"},
		Methods:      []string{"GET", "POST"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule target = %#v; want %#v", got, want)
	}
	again, err := NormalizeRuleTarget(got)
	if err != nil || !reflect.DeepEqual(again, got) {
		t.Fatalf("canonical rule target is not idempotent: %#v, %v", again, err)
	}

	for _, input := range []RuleTarget{
		{},
		{Host: "example.com", Schemes: []string{"ftp"}},
		{Host: "example.com", Ports: []int{0}},
		{Host: "example.com", Ports: []int{65536}},
		{Host: "example.com", PathPrefixes: []string{""}},
		{Host: "example.com", PathPrefixes: []string{"relative"}},
		{Host: "example.com", Methods: []string{""}},
		{Host: "example.com", Methods: []string{"GET\nPOST"}},
	} {
		if _, err := NormalizeRuleTarget(input); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("NormalizeRuleTarget(%#v) error = %v", input, err)
		}
	}
}
