// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry holds what leaves the server over OTLP: the switches, the
// log filters, the export error handler and the health check.
package telemetry

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otelhelper "github.com/Bugs5382/go-otel"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
)

// LogFields are the only log fields that may be exported. Export is
// default-deny, so a new field stays local until it is added here. A field
// holding anything a caller or a target system supplied stays off: sub (a
// Hydra subject or a token label), run, secret_id and format (tool arguments),
// path, reason, error, and the configured URLs and names.
var LogFields = []string{
	// http
	"method", "status", "dur",
	// mcp tool call
	"tool", "outcome",
	// mcp starting
	"hydra", "api_tokens",
	// go-buildinfo's dependency state changes
	"dependency", "required", "from", "to", "error_class",
}

var redactPatterns = []*regexp.Regexp{regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`)}

// InsecureSkipVerify reports OTLP_INSECURE_SKIP_VERIFY, which only "true" sets.
func InsecureSkipVerify() bool { return os.Getenv("OTLP_INSECURE_SKIP_VERIFY") == "true" }

// LogsEnabled reports OTLP_LOGS_ENABLED, which only "true" sets.
func LogsEnabled() bool { return os.Getenv("OTLP_LOGS_ENABLED") == "true" }

// InitOptions are the options for otel.InitWithOptions.
func InitOptions(skipVerify, logs bool) []otelhelper.Option {
	return []otelhelper.Option{
		otelhelper.WithInsecureSkipVerify(skipVerify),
		otelhelper.WithLogs(logs),
		otelhelper.WithLogAllowFields(LogFields...),
		otelhelper.WithLogRedactPatterns(redactPatterns...),
	}
}

// LogOptions adds the exporter beside stdout when logs are on. The writer
// discards everything until Init, so a logger can be built before it.
func LogOptions(logs bool) []log.Option {
	if !logs {
		return nil
	}
	return []log.Option{log.WithOutput(io.MultiWriter(os.Stdout, otelhelper.LogWriter()))}
}

// NewLogger builds the server's zerolog logger with LogOptions. go-log takes
// options only on its neutral logger, and Ctx is how to get the zerolog logger
// that one built.
func NewLogger(service string, logs bool) zerolog.Logger {
	log.NewLoggerWithOptions(service, LogOptions(logs)...)
	return log.Ctx(context.Background()) //nolint:staticcheck // no other way to a zerolog logger with options
}

// InstallErrorHandler sends OpenTelemetry's errors to local in place of raw
// text on stderr. The error is left out because it can name the endpoint and
// headers. Pass a logger that writes to stdout only: exported, each failed
// export would queue a record that feeds the next one.
func InstallErrorHandler(local zerolog.Logger) {
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {
		local.Warn().Msg("otlp export failed")
	}))
}

var errExportFailing = errors.New("otlp export failing")

// ExportCheck is the otlp health check: failing when a signal's last error is
// newer than its last success. Logs count only when they are on. It returns a
// class, never the export error's text.
func ExportCheck(state func() otelhelper.ExportStatus, logs bool) func(context.Context) error {
	return func(context.Context) error {
		st := state()
		if failing(st.Traces) || failing(st.Metrics) || (logs && failing(st.Logs)) {
			return health.Classify(errExportFailing, "unavailable")
		}
		return nil
	}
}

func failing(s otelhelper.SignalStatus) bool { return s.LastErrorAt.After(s.LastSuccess) }
