// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

func TestCheckOutKeepsAnUntrustedCertificateApart(t *testing.T) {
	const reason = "untrusted certificate: the certificate for dc01.example.org expired"
	got := checkOut(gwclient.CheckStatus{Result: "UNTRUSTED_CERTIFICATE", Detail: reason})
	if got.Result != "untrusted_certificate" || got.Detail != reason {
		t.Fatalf("got %+v", got)
	}
}
