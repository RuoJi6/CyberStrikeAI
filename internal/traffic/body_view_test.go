package traffic

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func encodeContentForTest(t *testing.T, encoding string, content []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	switch encoding {
	case "gzip":
		writer := gzip.NewWriter(&output)
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "deflate":
		writer := zlib.NewWriter(&output)
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "deflate-raw":
		writer, err := flate.NewWriter(&output, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "br":
		writer := brotli.NewWriter(&output)
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "zstd":
		writer, err := zstd.NewWriter(&output)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test encoding %q", encoding)
	}
	return output.Bytes()
}

func TestBuildBodyViewDecodesHTTPContentEncodings(t *testing.T) {
	want := []byte("<html><body>完整响应</body></html>")
	for _, encoding := range []string{"gzip", "deflate", "deflate-raw", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			header := encoding
			if encoding == "deflate-raw" {
				header = "deflate"
			}
			view := BuildBodyView(encodeContentForTest(t, encoding, want), "text/html; charset=utf-8", header, true, MaxStoredBodyBytes)
			if view.Content != string(want) || view.Format != BodyViewFormatText || !view.Decoded || !view.Complete || view.Error != "" || view.ContentEncoding != header {
				t.Fatalf("view = %#v", view)
			}
		})
	}
}

func TestBuildBodyViewDecodesStackedEncodingsInReverseOrder(t *testing.T) {
	want := []byte(`{"message":"stacked"}`)
	brotliBody := encodeContentForTest(t, "br", want)
	wireBody := encodeContentForTest(t, "gzip", brotliBody)
	view := BuildBodyView(wireBody, "application/json", "br, gzip", true, MaxStoredBodyBytes)
	if view.Content != string(want) || view.ContentEncoding != "br, gzip" || !view.Decoded || !view.Complete {
		t.Fatalf("view = %#v", view)
	}
}

func TestBuildBodyViewBoundsDecodedOutputAndUsesHexForBinary(t *testing.T) {
	compressed := encodeContentForTest(t, "br", []byte("0123456789"))
	view := BuildBodyView(compressed, "text/plain", "br", true, 5)
	if view.Content != "01234" || view.StoredBytes != 5 || view.Complete || !view.Decoded {
		t.Fatalf("bounded view = %#v", view)
	}

	binary := []byte{0, 1, 2, 0xff}
	view = BuildBodyView(binary, "application/octet-stream", "", true, MaxStoredBodyBytes)
	if view.Format != BodyViewFormatHex || view.Content != hex.EncodeToString(binary) || !view.Complete {
		t.Fatalf("binary view = %#v", view)
	}
}

func TestBuildBodyViewFallsBackToRawHexOnInvalidOrUnsupportedEncoding(t *testing.T) {
	for name, encoding := range map[string]string{"invalid": "br", "unsupported": "compress"} {
		t.Run(name, func(t *testing.T) {
			wire := []byte{0xff, 0x00, 0x7f}
			view := BuildBodyView(wire, "text/html", encoding, true, MaxStoredBodyBytes)
			if view.Format != BodyViewFormatHex || view.Content != hex.EncodeToString(wire) || view.Decoded || !view.Complete || view.Error == "" {
				t.Fatalf("fallback view = %#v", view)
			}
		})
	}
}

func TestBuildMessageBodyViewDoesNotDoubleDecodeTransformOutput(t *testing.T) {
	body, encoding, digest := EncodeBody([]byte("already decoded"))
	message := Message{
		Stage: StageDecodedResponse, Kind: MessageKindResponse, Status: 200,
		Headers: []Header{{Name: "Content-Encoding", Value: "br"}}, ContentType: "text/plain",
		Body: body, BodyEncoding: encoding, BodySHA256: digest,
		BodyLength: 15, BodyStoredBytes: 15, Complete: true,
	}
	view, err := BuildMessageBodyView(message)
	if err != nil || view.Content != "already decoded" || view.Decoded || view.Error != "" {
		t.Fatalf("view = %#v, err=%v", view, err)
	}
}
