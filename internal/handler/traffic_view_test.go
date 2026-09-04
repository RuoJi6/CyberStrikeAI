package handler

import (
	"bytes"
	"testing"

	"cyberstrike-ai/internal/traffic"
	"github.com/andybalholm/brotli"
)

func TestAttachTrafficBodyViewsDecodesWireResponseWithoutReplacingEvidence(t *testing.T) {
	var compressed bytes.Buffer
	writer := brotli.NewWriter(&compressed)
	want := []byte("<html>历史响应</html>")
	if _, err := writer.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	wire := compressed.Bytes()
	body, encoding, digest := traffic.EncodeBody(wire)
	detail := &traffic.TransactionDetail{Messages: []traffic.Message{{
		Stage: traffic.StageUpstreamResponse, Kind: traffic.MessageKindResponse, Status: 200,
		Headers:     []traffic.Header{{Name: "Content-Type", Value: "text/html"}, {Name: "Content-Encoding", Value: "br"}},
		ContentType: "text/html", Body: body, BodyEncoding: encoding, BodySHA256: digest,
		BodyLength: int64(len(wire)), BodyStoredBytes: int64(len(wire)), Complete: true,
	}}}

	attachTrafficBodyViews(detail)
	message := detail.Messages[0]
	if message.Body != body || message.BodyEncoding != traffic.BodyEncodingBase64 {
		t.Fatalf("wire evidence changed: %#v", message)
	}
	if message.BodyView == nil || message.BodyView.Content != string(want) || !message.BodyView.Decoded || message.BodyView.ContentEncoding != "br" {
		t.Fatalf("body view = %#v", message.BodyView)
	}

	redactTrafficDetail(detail)
	if detail.Messages[0].Body != "" || detail.Messages[0].BodyView != nil {
		t.Fatalf("sensitive projection was not redacted: %#v", detail.Messages[0])
	}
}
