// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	otelhelper "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const exportCanary = "canaryZx81"

type recording struct {
	mu   sync.Mutex
	seen []string
}

func (r *recording) add(m proto.Message) error {
	b, err := protojson.Marshal(m)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, string(b))
	return nil
}

func (r *recording) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.seen, "\n")
}

type traceSink struct {
	coltrace.UnimplementedTraceServiceServer
	*recording
}

func (s traceSink) Export(_ context.Context, m *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	return &coltrace.ExportTraceServiceResponse{}, s.add(m)
}

type metricSink struct {
	colmetrics.UnimplementedMetricsServiceServer
	*recording
}

func (s metricSink) Export(_ context.Context, m *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	return &colmetrics.ExportMetricsServiceResponse{}, s.add(m)
}

type logSink struct {
	collogs.UnimplementedLogsServiceServer
	*recording
}

func (s logSink) Export(_ context.Context, m *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	return &collogs.ExportLogsServiceResponse{}, s.add(m)
}

// TestExport_CanariesStayOffEverySignal drives the real handler and then plants
// a canary everywhere a library could, through the real exporters.
func TestExport_CanariesStayOffEverySignal(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recording{}
	srv := grpc.NewServer()
	coltrace.RegisterTraceServiceServer(srv, traceSink{recording: rec})
	colmetrics.RegisterMetricsServiceServer(srv, metricSink{recording: rec})
	collogs.RegisterLogsServiceServer(srv, logSink{recording: rec})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.name="+exportCanary)
	shutdown, err := otelhelper.InitWithOptions(t.Context(), serviceName, "http://"+lis.Addr().String(), telemetry.InitOptions(false, true)...)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config{GatewayURL: "http://192.0.2.1/graphql", AcceptAPITokens: true}
	handler, err := buildHandler(t.Context(), cfg, telemetry.NewLogger(serviceName, true))
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(otelhelper.Metrics(handler))
	defer front.Close()

	for _, q := range []struct{ method, path string }{
		{http.MethodGet, "/" + exportCanary},
		{http.MethodPost, "/mcp?arg=" + exportCanary},
		{exportCanary, "/mcp"},
	} {
		req, err := http.NewRequest(q.method, front.URL+q.path, strings.NewReader(`{"arguments":"`+exportCanary+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Baggage", "member="+exportCanary)
		req.Header.Set("Authorization", "Bearer "+exportCanary)
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	ctx := otel.GetTextMapPropagator().Extract(t.Context(), propagation.MapCarrier{"baggage": "member=" + exportCanary})
	out := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, out)
	if strings.Contains(out.Get("baggage"), exportCanary) {
		t.Fatalf("baggage was forwarded: %v", out)
	}

	_, span := otel.Tracer("test").Start(ctx, "tool "+exportCanary)
	span.SetAttributes(attribute.String("tool.argument", exportCanary))
	span.RecordError(errors.New(exportCanary))
	span.SetStatus(codes.Error, exportCanary)
	span.End()

	counter := otelhelper.Counter("mcp.test.calls", "Test calls.")
	counter.Add(t.Context(), 1, metric.WithAttributes(attribute.String("tool.result", exportCanary)))

	flush, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdown(flush); err != nil {
		t.Fatal(err)
	}

	got := rec.text()
	for _, want := range []string{"http.route", "/mcp", "unmatched", "_OTHER", "mcp.test.calls", "[span]", `"http"`} {
		if !strings.Contains(got, want) {
			t.Errorf("%s never arrived, so the test proved nothing: %s", want, got)
		}
	}
	if strings.Contains(got, exportCanary) {
		t.Fatalf("a canary reached the collector: %s", got)
	}
}

func TestExport_ErrorTextStaysOffTheLocalLog(t *testing.T) {
	var buf bytes.Buffer
	prev := stdlog.Writer()
	stdlog.SetOutput(&buf)
	t.Cleanup(func() { stdlog.SetOutput(prev) })

	shutdown, err := otelhelper.InitWithOptions(t.Context(), serviceName, "", telemetry.InitOptions(false, false)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	otel.Handle(errors.New("dial collector.example.test:4317 authorization=" + exportCanary))
	if got := buf.String(); strings.Contains(got, exportCanary) || strings.Contains(got, "example.test") {
		t.Fatalf("export text reached the log: %q", got)
	}
}
