// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	otelhelper "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/telemetry"
	"github.com/rs/zerolog"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

const canary = "canary-Zx81-should-not-leave"

type fakeCollector struct {
	collogs.UnimplementedLogsServiceServer
	mu   sync.Mutex
	seen []string
}

func (c *fakeCollector) Export(_ context.Context, r *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	b, err := protojson.Marshal(r)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, string(b))
	return &collogs.ExportLogsServiceResponse{}, nil
}

func (c *fakeCollector) received() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.seen, "\n")
}

func startCollector(t *testing.T) (*fakeCollector, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeCollector{}
	s := grpc.NewServer()
	collogs.RegisterLogsServiceServer(s, c)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return c, "http://" + lis.Addr().String()
}

// exportLine writes one line through the real exporter and returns what the
// collector received.
func exportLine(t *testing.T, write func(zerolog.Logger)) string {
	t.Helper()
	c, endpoint := startCollector(t)
	shutdown, err := otelhelper.InitWithOptions(t.Context(), "mcp", endpoint, telemetry.InitOptions(false, true)...)
	if err != nil {
		t.Fatal(err)
	}
	write(telemetry.NewLogger("mcp", true))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = shutdown(ctx)
	return c.received()
}

func TestLogExport_UnallowedFieldsNeverReachTheCollector(t *testing.T) {
	got := exportLine(t, func(l zerolog.Logger) {
		l.Info().
			Str("tool", "sneakers_get_secret").Str("tool_status", "ok").Dur("dur", time.Second).
			Str("sub", canary).Str("outcome", canary).Str("method", canary).Str("run", canary).Str("secret_id", canary).Str("format", canary).
			Str("path", "/mcp?"+canary).Str("reason", canary).Str("error", canary).
			Str("issuer", canary).Str("gateway", canary).Str("args", canary).
			Msg("mcp tool call")
	})
	if !strings.Contains(got, "sneakers_get_secret") || !strings.Contains(got, "mcp tool call") {
		t.Fatalf("the allowed fields never arrived: %s", got)
	}
	if strings.Contains(got, canary) {
		t.Fatalf("a canary reached the collector: %s", got)
	}
}

func TestLogExport_TokenShapeIsRedactedInAnAllowedField(t *testing.T) {
	token := "snk_" + "abc123_DEF-456"
	got := exportLine(t, func(l zerolog.Logger) {
		l.Warn().Str("tool_status", "bad "+token).Msg("mcp tool call")
	})
	if !strings.Contains(got, "mcp tool call") {
		t.Fatalf("the line never arrived: %s", got)
	}
	if strings.Contains(got, token) {
		t.Fatalf("a token reached the collector: %s", got)
	}
}

func TestLogExport_DebugNeverLeaves(t *testing.T) {
	t.Setenv("LOG_LEVEL", "trace")
	got := exportLine(t, func(l zerolog.Logger) { l.Debug().Str("tool", "x").Msg(canary) })
	if strings.Contains(got, canary) {
		t.Fatalf("a debug line reached the collector: %s", got)
	}
}

func TestLogFields_HoldNothingThatCarriesAValue(t *testing.T) {
	for _, f := range []string{"outcome", "method", "sub", "run", "secret_id", "format", "fingerprint", "path", "reason", "error", "issuer", "audience", "resource", "gateway", "http"} {
		if slices.Contains(telemetry.LogFields, f) {
			t.Errorf("%q must stay off the allow-list", f)
		}
	}
}

func TestEnvSwitches_OnlyTrueCounts(t *testing.T) {
	for v, want := range map[string]bool{"": false, "true": true, "TRUE": false, "1": false, "false": false} {
		t.Setenv("OTLP_LOGS_ENABLED", v)
		t.Setenv("OTLP_INSECURE_SKIP_VERIFY", v)
		if telemetry.LogsEnabled() != want || telemetry.InsecureSkipVerify() != want {
			t.Errorf("%q: got %v and %v, want %v", v, telemetry.LogsEnabled(), telemetry.InsecureSkipVerify(), want)
		}
	}
}

func TestLogOptions_LogsOffLeavesTheWriterAlone(t *testing.T) {
	if got := telemetry.LogOptions(false); len(got) != 0 {
		t.Fatalf("logs off: got %d log options", len(got))
	}
	if got := telemetry.LogOptions(true); len(got) != 1 {
		t.Fatalf("logs on: got %d log options", len(got))
	}
}

func TestExportCheck(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(time.Second)
	failing := otelhelper.SignalStatus{LastSuccess: t0, LastErrorAt: t1, LastError: "dial collector.example.test"}
	healthy := otelhelper.SignalStatus{LastSuccess: t1, LastErrorAt: t0, LastError: "old"}
	for name, tc := range map[string]struct {
		st      otelhelper.ExportStatus
		logs    bool
		wantErr bool
	}{
		"nothing yet":        {},
		"recovered":          {st: otelhelper.ExportStatus{Traces: healthy, Metrics: healthy}},
		"traces failing":     {st: otelhelper.ExportStatus{Traces: failing}, wantErr: true},
		"metrics failing":    {st: otelhelper.ExportStatus{Metrics: failing}, wantErr: true},
		"logs failing, off":  {st: otelhelper.ExportStatus{Logs: failing}},
		"logs failing, on":   {st: otelhelper.ExportStatus{Logs: failing}, logs: true, wantErr: true},
		"failed, no success": {st: otelhelper.ExportStatus{Traces: otelhelper.SignalStatus{LastErrorAt: t0}}, wantErr: true},
	} {
		err := telemetry.ExportCheck(func() otelhelper.ExportStatus { return tc.st }, tc.logs)(t.Context())
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, want error %v", name, err, tc.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), "example.test") {
			t.Errorf("%s: the error carries export text: %v", name, err)
		}
	}
}
