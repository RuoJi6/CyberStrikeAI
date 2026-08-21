package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"cyberstrike-ai/internal/boundary"
)

const (
	tlsRecordHeaderBytes  = 5
	tlsHandshakeRecord    = 22
	tlsClientHelloType    = 1
	tlsServerNameType     = 0
	tlsEncryptedHelloType = 0xfe0d
	tlsEncryptedSNIType   = 0xffce
	defaultMaxClientHello = 64 << 10
)

var ErrInvalidClientHello = errors.New("invalid TLS ClientHello")

// readClientHelloSNI consumes exactly the TLS records needed to obtain the
// first ClientHello. raw contains every consumed byte so the proxy can forward
// the handshake unchanged after policy and SNI validation.
func readClientHelloSNI(reader io.Reader, maxBytes int) ([]byte, string, error) {
	if reader == nil {
		return nil, "", fmt.Errorf("%w: reader is required", ErrInvalidClientHello)
	}
	if maxBytes <= tlsRecordHeaderBytes+4 {
		return nil, "", fmt.Errorf("%w: byte limit is too small", ErrInvalidClientHello)
	}
	var raw, handshake []byte
	expectedHandshakeBytes := 0
	for expectedHandshakeBytes == 0 || len(handshake) < expectedHandshakeBytes {
		var header [tlsRecordHeaderBytes]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, "", fmt.Errorf("%w: read TLS record header: %v", ErrInvalidClientHello, err)
		}
		if header[0] != tlsHandshakeRecord || header[1] != 3 || header[2] > 4 {
			return nil, "", fmt.Errorf("%w: first flight is not a TLS handshake", ErrInvalidClientHello)
		}
		recordBytes := int(binary.BigEndian.Uint16(header[3:5]))
		if recordBytes == 0 || len(raw)+tlsRecordHeaderBytes+recordBytes > maxBytes {
			return nil, "", fmt.Errorf("%w: TLS ClientHello exceeds byte limit", ErrInvalidClientHello)
		}
		payload := make([]byte, recordBytes)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, "", fmt.Errorf("%w: read TLS handshake record: %v", ErrInvalidClientHello, err)
		}
		raw = append(raw, header[:]...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) >= 1 && handshake[0] != tlsClientHelloType {
			return nil, "", fmt.Errorf("%w: first handshake message is not ClientHello", ErrInvalidClientHello)
		}
		if len(handshake) >= 4 && expectedHandshakeBytes == 0 {
			expectedHandshakeBytes = 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if expectedHandshakeBytes < 4 || expectedHandshakeBytes > maxBytes {
				return nil, "", fmt.Errorf("%w: declared ClientHello length is invalid", ErrInvalidClientHello)
			}
		}
	}
	serverName, err := parseClientHelloServerName(handshake[4:expectedHandshakeBytes])
	if err != nil {
		return nil, "", err
	}
	return raw, serverName, nil
}

func parseClientHelloServerName(body []byte) (string, error) {
	// legacy_version + random + session id length
	if len(body) < 2+32+1 {
		return "", fmt.Errorf("%w: truncated ClientHello", ErrInvalidClientHello)
	}
	position := 2 + 32
	sessionBytes := int(body[position])
	position++
	if sessionBytes > 32 || position+sessionBytes+2 > len(body) {
		return "", fmt.Errorf("%w: invalid ClientHello session id", ErrInvalidClientHello)
	}
	position += sessionBytes
	cipherBytes := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if cipherBytes < 2 || cipherBytes%2 != 0 || position+cipherBytes+1 > len(body) {
		return "", fmt.Errorf("%w: invalid ClientHello cipher suites", ErrInvalidClientHello)
	}
	position += cipherBytes
	compressionBytes := int(body[position])
	position++
	if compressionBytes < 1 || position+compressionBytes+2 > len(body) {
		return "", fmt.Errorf("%w: invalid ClientHello compression methods", ErrInvalidClientHello)
	}
	position += compressionBytes
	extensionBytes := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if extensionBytes == 0 || position+extensionBytes != len(body) {
		return "", fmt.Errorf("%w: invalid ClientHello extensions", ErrInvalidClientHello)
	}
	extensions := body[position:]
	serverName := ""
	seenServerNameExtension := false
	for len(extensions) != 0 {
		if len(extensions) < 4 {
			return "", fmt.Errorf("%w: truncated ClientHello extension", ErrInvalidClientHello)
		}
		typeID := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if length > len(extensions) {
			return "", fmt.Errorf("%w: invalid ClientHello extension length", ErrInvalidClientHello)
		}
		value := extensions[:length]
		extensions = extensions[length:]
		if typeID == tlsEncryptedHelloType || typeID == tlsEncryptedSNIType {
			return "", fmt.Errorf("%w: encrypted ClientHello/SNI is not allowed", ErrInvalidClientHello)
		}
		if typeID != tlsServerNameType {
			continue
		}
		if seenServerNameExtension {
			return "", fmt.Errorf("%w: duplicate SNI extension", ErrInvalidClientHello)
		}
		seenServerNameExtension = true
		parsed, err := parseServerNameExtension(value)
		if err != nil {
			return "", err
		}
		serverName = parsed
	}
	if serverName == "" {
		return "", fmt.Errorf("%w: ClientHello has no DNS SNI", ErrInvalidClientHello)
	}
	return serverName, nil
}

func parseServerNameExtension(value []byte) (string, error) {
	if len(value) < 2 {
		return "", fmt.Errorf("%w: truncated SNI list", ErrInvalidClientHello)
	}
	listBytes := int(binary.BigEndian.Uint16(value[:2]))
	if listBytes == 0 || listBytes != len(value)-2 {
		return "", fmt.Errorf("%w: invalid SNI list length", ErrInvalidClientHello)
	}
	entries := value[2:]
	serverName := ""
	for len(entries) != 0 {
		if len(entries) < 3 {
			return "", fmt.Errorf("%w: truncated SNI entry", ErrInvalidClientHello)
		}
		nameType := entries[0]
		nameBytes := int(binary.BigEndian.Uint16(entries[1:3]))
		entries = entries[3:]
		if nameBytes == 0 || nameBytes > len(entries) {
			return "", fmt.Errorf("%w: invalid SNI entry length", ErrInvalidClientHello)
		}
		name := string(entries[:nameBytes])
		entries = entries[nameBytes:]
		if nameType != 0 {
			continue
		}
		if serverName != "" || name != strings.TrimSpace(name) {
			return "", fmt.Errorf("%w: duplicate or non-canonical DNS SNI", ErrInvalidClientHello)
		}
		for index := 0; index < len(name); index++ {
			if name[index] == 0 || name[index] > 0x7f {
				return "", fmt.Errorf("%w: DNS SNI must be ASCII", ErrInvalidClientHello)
			}
		}
		canonical, err := boundary.NormalizeHost(name)
		if err != nil {
			return "", fmt.Errorf("%w: normalize DNS SNI: %v", ErrInvalidClientHello, err)
		}
		if _, err := netip.ParseAddr(canonical); err == nil {
			return "", fmt.Errorf("%w: SNI must be a DNS name", ErrInvalidClientHello)
		}
		serverName = canonical
	}
	return serverName, nil
}
