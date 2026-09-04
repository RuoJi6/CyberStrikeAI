package traffic

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	BodyViewFormatText = "text"
	BodyViewFormatHex  = "hex"

	BodyViewErrorDecodeFailed        = "content_decoding_failed"
	BodyViewErrorUnsupportedEncoding = "unsupported_content_encoding"
)

// BodyView is a presentation projection of immutable wire evidence. Content
// contains either decoded text or hexadecimal bytes; raw message bytes and
// their SHA-256 remain untouched in Message.Body.
type BodyView struct {
	Content         string `json:"content,omitempty"`
	Format          string `json:"format"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	Decoded         bool   `json:"decoded,omitempty"`
	Complete        bool   `json:"complete"`
	StoredBytes     int64  `json:"stored_bytes"`
	Error           string `json:"error,omitempty"`
}

// BuildBodyView decodes HTTP content codings for display without modifying the
// captured wire bytes. At most maxBytes of decoded data are materialized.
func BuildBodyView(content []byte, contentType, contentEncoding string, complete bool, maxBytes int64) BodyView {
	if maxBytes <= 0 {
		maxBytes = MaxStoredBodyBytes
	}
	view := BodyView{
		Format:          BodyViewFormatText,
		ContentEncoding: normalizeContentEncoding(contentEncoding),
		Complete:        complete,
	}
	if len(content) == 0 {
		view.ContentEncoding = ""
		return view
	}

	display := content
	if view.ContentEncoding != "" {
		decoded, truncated, err := decodeHTTPContent(content, view.ContentEncoding, maxBytes)
		if err == nil {
			display = decoded
			view.Decoded = true
			view.Complete = view.Complete && !truncated
		} else {
			view.Complete = complete
			if errors.Is(err, errUnsupportedContentEncoding) {
				view.Error = BodyViewErrorUnsupportedEncoding
			} else {
				view.Error = BodyViewErrorDecodeFailed
			}
		}
	}

	if !view.Decoded || view.ContentEncoding == "" {
		if int64(len(display)) > maxBytes {
			display = display[:maxBytes]
			view.Complete = false
		}
	}
	view.StoredBytes = int64(len(display))
	if isTextualContent(contentType) && utf8.Valid(display) {
		view.Content = string(display)
		return view
	}
	view.Format = BodyViewFormatHex
	view.Content = hex.EncodeToString(display)
	return view
}

// BuildMessageBodyView produces a view for an already validated traffic
// message. Traffic Transform decoded stages are treated as final application
// content so an inherited wire Content-Encoding header is never applied twice.
func BuildMessageBodyView(message Message) (BodyView, error) {
	content, err := DecodeBody(message)
	if err != nil {
		return BodyView{}, err
	}
	contentEncoding := ""
	if message.Stage != StageDecodedRequest && message.Stage != StageDecodedResponse {
		contentEncoding = HeaderValue(message.Headers, "Content-Encoding")
	}
	return BuildBodyView(content, message.ContentType, contentEncoding, message.Complete, MaxStoredBodyBytes), nil
}

func HeaderValue(headers []Header, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func normalizeContentEncoding(value string) string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" && part != "identity" {
			result = append(result, part)
		}
	}
	return strings.Join(result, ", ")
}

var errUnsupportedContentEncoding = errors.New("unsupported HTTP content encoding")

func decodeHTTPContent(content []byte, contentEncoding string, maxBytes int64) ([]byte, bool, error) {
	encodings := strings.Split(contentEncoding, ",")
	decoded := append([]byte(nil), content...)
	for index := len(encodings) - 1; index >= 0; index-- {
		encoding := strings.ToLower(strings.TrimSpace(encodings[index]))
		if encoding == "" || encoding == "identity" {
			continue
		}
		var err error
		var truncated bool
		decoded, truncated, err = decodeHTTPContentLayer(decoded, encoding, maxBytes)
		if err != nil {
			return nil, false, err
		}
		if truncated {
			if index != 0 {
				return nil, false, fmt.Errorf("decode intermediate %s layer exceeds limit", encoding)
			}
			return decoded, true, nil
		}
	}
	return decoded, false, nil
}

func decodeHTTPContentLayer(content []byte, encoding string, maxBytes int64) ([]byte, bool, error) {
	var reader io.Reader
	var closeReader func()
	switch encoding {
	case "gzip", "x-gzip":
		decoder, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, false, err
		}
		reader, closeReader = decoder, func() { _ = decoder.Close() }
	case "deflate":
		decoder, err := zlib.NewReader(bytes.NewReader(content))
		if err == nil {
			reader, closeReader = decoder, func() { _ = decoder.Close() }
		} else {
			rawDecoder := flate.NewReader(bytes.NewReader(content))
			reader, closeReader = rawDecoder, func() { _ = rawDecoder.Close() }
		}
	case "br":
		reader = brotli.NewReader(bytes.NewReader(content))
	case "zstd":
		memoryLimit := uint64(64 << 20)
		if candidate := uint64(maxBytes) * 2; candidate > memoryLimit {
			memoryLimit = candidate
		}
		decoder, err := zstd.NewReader(
			bytes.NewReader(content), zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(memoryLimit),
		)
		if err != nil {
			return nil, false, err
		}
		reader, closeReader = decoder, decoder.Close
	default:
		return nil, false, fmt.Errorf("%w: %s", errUnsupportedContentEncoding, encoding)
	}
	if closeReader != nil {
		defer closeReader()
	}
	limited := io.LimitReader(reader, maxBytes+1)
	decoded, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(decoded)) > maxBytes {
		return decoded[:maxBytes], true, nil
	}
	return decoded, false, nil
}

func isTextualContent(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	mediaType = strings.ToLower(mediaType)
	return mediaType == "" || strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "json") ||
		strings.Contains(mediaType, "xml") || strings.Contains(mediaType, "javascript") ||
		mediaType == "application/x-www-form-urlencoded" || mediaType == "application/graphql"
}
