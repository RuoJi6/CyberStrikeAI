package egress

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReadClientHelloSNIAcceptsCanonicalAndFragmentedHandshake(t *testing.T) {
	for _, split := range []int{0, 7, 41} {
		wire := testClientHello("Allowed.Example.", split)
		raw, serverName, err := readClientHelloSNI(bytes.NewReader(wire), defaultMaxClientHello)
		if err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		if serverName != "allowed.example" || !bytes.Equal(raw, wire) {
			t.Fatalf("split %d: serverName=%q rawEqual=%v", split, serverName, bytes.Equal(raw, wire))
		}
	}
}

func TestReadClientHelloSNIParsesRealGoTLSClient(t *testing.T) {
	clientSide, gatewaySide := net.Pipe()
	defer clientSide.Close()
	defer gatewaySide.Close()
	done := make(chan error, 1)
	go func() {
		client := tls.Client(clientSide, &tls.Config{ServerName: "allowed.example", MinVersion: tls.VersionTLS12})
		done <- client.Handshake()
	}()
	_ = gatewaySide.SetReadDeadline(time.Now().Add(time.Second))
	raw, serverName, err := readClientHelloSNI(gatewaySide, defaultMaxClientHello)
	if err != nil {
		t.Fatal(err)
	}
	if serverName != "allowed.example" || len(raw) < 100 {
		t.Fatalf("real ClientHello = serverName %q, bytes %d", serverName, len(raw))
	}
	_ = gatewaySide.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS client did not stop")
	}
}

func TestReadClientHelloSNIRejectsMissingDuplicateMalformedAndOversizedInput(t *testing.T) {
	missing := testClientHelloWithExtensions(nil, 0)
	if _, _, err := readClientHelloSNI(bytes.NewReader(missing), defaultMaxClientHello); !errors.Is(err, ErrInvalidClientHello) {
		t.Fatalf("missing SNI error = %v", err)
	}
	sni := testSNIExtension("allowed.example")
	duplicate := testClientHelloWithExtensions(append(append([]byte{}, sni...), sni...), 0)
	if _, _, err := readClientHelloSNI(bytes.NewReader(duplicate), defaultMaxClientHello); !errors.Is(err, ErrInvalidClientHello) {
		t.Fatalf("duplicate SNI error = %v", err)
	}
	ech := append(append([]byte{}, sni...), byte(tlsEncryptedHelloType>>8), byte(tlsEncryptedHelloType&0xff), 0, 0)
	if _, _, err := readClientHelloSNI(bytes.NewReader(testClientHelloWithExtensions(ech, 0)), defaultMaxClientHello); !errors.Is(err, ErrInvalidClientHello) {
		t.Fatalf("ECH error = %v", err)
	}
	malformed := testClientHello("allowed.example", 0)
	malformed[3], malformed[4] = 0xff, 0xff
	if _, _, err := readClientHelloSNI(bytes.NewReader(malformed), defaultMaxClientHello); !errors.Is(err, ErrInvalidClientHello) {
		t.Fatalf("malformed record error = %v", err)
	}
	valid := testClientHello("allowed.example", 0)
	if _, _, err := readClientHelloSNI(bytes.NewReader(valid), len(valid)-1); !errors.Is(err, ErrInvalidClientHello) {
		t.Fatalf("oversized ClientHello error = %v", err)
	}
}

func TestReadClientHelloSNIRejectsIPAndNonASCIINames(t *testing.T) {
	for _, name := range []string{"8.8.8.8", "tést.example"} {
		if _, _, err := readClientHelloSNI(bytes.NewReader(testClientHello(name, 0)), defaultMaxClientHello); !errors.Is(err, ErrInvalidClientHello) {
			t.Fatalf("SNI %q error = %v", name, err)
		}
	}
}

func TestReadClientHelloForIPTargetAllowsOnlyMissingSNI(t *testing.T) {
	wire := testClientHelloWithExtensions(nil, 0)
	raw, serverName, err := readClientHelloForTarget(bytes.NewReader(wire), defaultMaxClientHello, "47.116.200.74")
	if err != nil || serverName != "" || !bytes.Equal(raw, wire) {
		t.Fatalf("IP ClientHello = name %q / raw %v / error %v", serverName, bytes.Equal(raw, wire), err)
	}
	if !clientHelloMatchesTarget("", "47.116.200.74") {
		t.Fatal("missing SNI must be accepted for an explicit IP CONNECT target")
	}
	if clientHelloMatchesTarget("other.example", "47.116.200.74") || clientHelloMatchesTarget("", "allowed.example") {
		t.Fatal("missing or different SNI must not be accepted for a DNS CONNECT target")
	}
	if _, _, err := readClientHelloForTarget(bytes.NewReader(wire), defaultMaxClientHello, "allowed.example"); !errors.Is(err, ErrInvalidClientHello) {
		t.Fatalf("DNS target missing SNI error = %v", err)
	}
}

func testClientHello(serverName string, split int) []byte {
	return testClientHelloWithExtensions(testSNIExtension(serverName), split)
}

func testSNIExtension(serverName string) []byte {
	name := []byte(serverName)
	entry := []byte{0, byte(len(name) >> 8), byte(len(name))}
	entry = append(entry, name...)
	value := []byte{byte(len(entry) >> 8), byte(len(entry))}
	value = append(value, entry...)
	extension := []byte{0, 0, byte(len(value) >> 8), byte(len(value))}
	return append(extension, value...)
}

func testClientHelloWithExtensions(extensions []byte, split int) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)             // session id
	body = append(body, 0, 2, 0x13, 1) // one cipher suite
	body = append(body, 1, 0)          // null compression
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{tlsClientHelloType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	if split <= 0 || split >= len(handshake) {
		return testTLSRecord(handshake)
	}
	return append(testTLSRecord(handshake[:split]), testTLSRecord(handshake[split:])...)
}

func testTLSRecord(payload []byte) []byte {
	header := []byte{tlsHandshakeRecord, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(payload)))
	return append(header, payload...)
}
