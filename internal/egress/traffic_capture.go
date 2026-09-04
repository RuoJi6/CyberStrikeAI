package egress

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/networkprovenance"
	"cyberstrike-ai/internal/traffic"
)

const (
	trafficAgentIDHeader     = "X-Cyberstrike-Agent-Id"
	trafficExecutionIDHeader = "X-Cyberstrike-Execution-Id"
	trafficToolCallIDHeader  = "X-Cyberstrike-Tool-Call-Id"
)

type TrafficSink func(context.Context, traffic.Transaction, []traffic.Message) error

type trafficAttribution struct {
	provenance networkprovenance.NetworkProvenanceV1
}

type fullBodyCapture struct {
	content bytes.Buffer
	total   int64
}

func (capture *fullBodyCapture) Write(content []byte) (int, error) {
	capture.total += int64(len(content))
	remaining := traffic.MaxStoredBodyBytes - capture.content.Len()
	if remaining > len(content) {
		remaining = len(content)
	}
	if remaining > 0 {
		_, _ = capture.content.Write(content[:remaining])
	}
	return len(content), nil
}

func (capture *fullBodyCapture) message(
	transactionID, stage, kind, method, path string,
	status int,
	protocol string,
	headers []traffic.Header,
	createdAt time.Time,
) traffic.Message {
	stored := capture.content.Bytes()
	body, encoding, digest := traffic.EncodeBody(stored)
	return traffic.Message{
		TransactionID:   transactionID,
		Stage:           stage,
		Kind:            kind,
		Method:          method,
		Path:            path,
		Status:          status,
		Protocol:        protocol,
		Headers:         headers,
		ContentType:     trafficContentType(headers),
		Body:            body,
		BodyEncoding:    encoding,
		BodySHA256:      digest,
		BodyLength:      capture.total,
		BodyStoredBytes: int64(len(stored)),
		Complete:        capture.total == int64(len(stored)),
		CreatedAt:       createdAt.UTC(),
	}
}

func (capture *fullBodyCapture) packetSnapshot(contentType, contentEncoding string) (body, encoding string, truncated, decoded bool, normalizedContentEncoding string) {
	view := traffic.BuildBodyView(
		capture.content.Bytes(), contentType, contentEncoding,
		capture.total == int64(capture.content.Len()), MaxHTTPPacketBodyBytes,
	)
	encoding = "utf8"
	if view.Format == traffic.BodyViewFormatHex {
		encoding = "hex"
	}
	if view.Content == "" {
		encoding = ""
	}
	return view.Content, encoding, !view.Complete, view.Decoded, view.ContentEncoding
}

func consumeTrafficAttribution(ctx context.Context, headers http.Header) trafficAttribution {
	stripLegacyAttributionHeaders(headers)
	return trafficAttribution{provenance: networkprovenance.FromContext(ctx)}
}

func boundedAttributionValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

func trafficHeaders(headers http.Header, host string) []traffic.Header {
	result := make([]traffic.Header, 0, len(headers)+1)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	for _, rawName := range names {
		name := http.CanonicalHeaderKey(rawName)
		if strings.EqualFold(name, "Proxy-Authorization") || strings.HasPrefix(strings.ToLower(name), "x-cyberstrike-") {
			continue
		}
		values := headers.Values(rawName)
		for _, value := range values {
			result = append(result, traffic.Header{Name: name, Value: value})
		}
	}
	if strings.TrimSpace(host) != "" {
		result = append(result, traffic.Header{Name: "Host", Value: strings.TrimSpace(host)})
	}
	return result
}

func trafficContentType(headers []traffic.Header) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, "Content-Type") {
			return header.Value
		}
	}
	return ""
}

func emitTraffic(sink TrafficSink, ctx context.Context, transaction traffic.Transaction, messages []traffic.Message) {
	if sink == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("traffic capture sink panicked for transaction %s", transaction.ID)
		}
	}()
	if err := sink(ctx, transaction, messages); err != nil {
		log.Printf("traffic capture sink failed for transaction %s: %v", transaction.ID, err)
	}
}
