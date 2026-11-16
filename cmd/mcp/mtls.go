// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"os"

	"github.com/Bugs5382/go-mtls"
	zlog "github.com/rs/zerolog/log"
)

// mtlsClient returns the HTTP client for every call to the gateway. With none
// of MTLS_CERT_FILE, MTLS_KEY_FILE and MTLS_CA_FILE set it returns nil and the
// callers keep their plaintext default. With all three set the client presents
// this service's certificate and checks the gateway's against the cluster CA
// (go-mtls reloads renewed files without a restart). A partly set trio, or a
// file that can't be read, is an error: it never falls back to plaintext.
func mtlsClient() (*http.Client, error) {
	if os.Getenv(mtls.EnvCertFile) == "" && os.Getenv(mtls.EnvKeyFile) == "" && os.Getenv(mtls.EnvCAFile) == "" {
		return nil, nil
	}
	files, err := mtls.FilesFromEnv()
	if err != nil {
		return nil, err
	}
	p, err := mtls.NewProvider(files, mtls.WithErrorHandler(func(err error) {
		// A renewal that can't be read leaves the last good files in use.
		zlog.Warn().Err(err).Msg("mtls: keeping the last good certificate files")
	}))
	if err != nil {
		return nil, errors.New("mtls: " + err.Error())
	}
	return p.HTTPClient(), nil
}

// healthClient is the client for the gateway readiness check: the mTLS one
// when configured, else a plain one, both with the check's short timeout.
func healthClient(cfg config) *http.Client {
	if cfg.gatewayHTTP == nil {
		return &http.Client{Timeout: checkTimeout}
	}
	c := *cfg.gatewayHTTP
	c.Timeout = checkTimeout
	return &c
}
