// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	certkit "github.com/Bugs5382/go-certkit"
)

// CAFileEnv names a PEM file of extra roots to trust for SNEAKERS_URL, such
// as a new appliance's own self-signed certificate. -ca-file wins over it.
const CAFileEnv = "SNEAKERS_CA_FILE"

// httpTimeout bounds every call the commands make to SNEAKERS_URL.
const httpTimeout = 30 * time.Second

// CAFile returns the CA file to use: the -ca-file flag, else SNEAKERS_CA_FILE.
func CAFile(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return flagValue
	}
	return getenv(CAFileEnv)
}

// HTTPClient returns the client the commands call SNEAKERS_URL with. With a
// caFile, the certificates in it are trusted on top of the system's roots;
// verification itself, the host name check included, is never turned off.
// A file that can't be read, that holds no certificate, or that also holds a
// private key is refused before any request is made.
func HTTPClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{Timeout: httpTimeout}, nil
	}
	pool, err := rootsWith(caFile)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: httpTimeout, Transport: tr}, nil
}

// rootsWith returns the system's roots plus every certificate in caFile.
func rootsWith(caFile string) (*x509.CertPool, error) {
	refuse := func(why string) error { return fmt.Errorf("%s %s: %s", CAFileEnv, caFile, why) }
	data, err := os.ReadFile(caFile) // #nosec G304 -- the file the person named to trust
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, refuse("can't read it: " + err.Error())
	}
	// The error from certkit can describe the content, and this file may be
	// a key by mistake, so only the outcome is reported.
	b, err := certkit.Parse(data, "")
	switch {
	case err != nil:
		return nil, refuse("it isn't a PEM certificate file")
	case len(b.KeyPEM) > 0:
		return nil, refuse("it holds a private key; give the certificate only")
	case len(b.LeafPEM) == 0:
		return nil, refuse("it holds no certificate")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, c := range append([][]byte{b.LeafPEM}, b.ChainPEM...) {
		if !pool.AppendCertsFromPEM(c) {
			return nil, refuse("a certificate in it doesn't parse")
		}
	}
	return pool, nil
}
