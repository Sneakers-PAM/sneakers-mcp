// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

const sshTypesReply = `{"data":{"secretTypes":[` +
	`{"id":"type-ssh-key","name":"SSH Key","fields":[` +
	`{"key":"username","label":"Username","kind":"TEXT","required":true,"sensitive":false},` +
	`{"key":"keyFormat","label":"Key Format","kind":"SELECT","required":true,"sensitive":false},` +
	`{"key":"publicKey","label":"Public Key","kind":"MULTILINE","required":false,"sensitive":false},` +
	`{"key":"privateKey","label":"Private Key","kind":"SENSITIVE","required":true,"sensitive":true},` +
	`{"key":"passphrase","label":"Passphrase","kind":"SENSITIVE","required":false,"sensitive":true},` +
	`{"key":"notes","label":"Notes","kind":"MULTILINE","required":false,"sensitive":false}]},` +
	`{"id":"type-password","name":"Password","fields":[` +
	`{"key":"username","label":"Username","kind":"TEXT","required":false,"sensitive":false},` +
	`{"key":"password","label":"Password","kind":"PASSWORD","required":true,"sensitive":true}]}]}}`

// sshGW answers secretTypes and createSecretForPrincipal, and records the
// fields the create carried.
type sshGW struct {
	*httptest.Server
	mu      sync.Mutex
	creates int
	fields  map[string]string
	vars    map[string]any
	reply   string
}

func sshGateway(t *testing.T, createReply string) *sshGW {
	t.Helper()
	g := &sshGW{reply: createReply}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "createSecretForPrincipal"):
			g.mu.Lock()
			g.creates++
			g.vars = req.Variables
			g.fields = map[string]string{}
			fs, _ := req.Variables["fields"].([]any)
			for _, f := range fs {
				m, _ := f.(map[string]any)
				k, _ := m["key"].(string)
				v, _ := m["value"].(string)
				g.fields[k] = v
			}
			g.mu.Unlock()
			_, _ = io.WriteString(w, g.reply)
		case strings.Contains(req.Query, "secretTypes"):
			_, _ = io.WriteString(w, sshTypesReply)
		default:
			http.Error(w, "unexpected operation", http.StatusBadRequest)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *sshGW) created() (int, map[string]string, map[string]any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.creates, g.fields, g.vars
}

const sshCreateOK = `{"data":{"createSecretForPrincipal":{"id":"s1","name":"deploy key","folderId":"f1","typeId":"type-ssh-key",` +
	`"placement":{"folderId":"f1","requestedFolderId":"f1","rule":"REQUESTED","reason":"requested"}}}}`

type keyCase struct {
	format  string
	keyType string
	bits    int
}

func TestGenerateSSHKeyStoresThePairAndReturnsOnlyThePublicHalf(t *testing.T) {
	cases := map[string]keyCase{
		"default":     {"", ssh.KeyAlgoED25519, 0},
		"Ed25519":     {"Ed25519", ssh.KeyAlgoED25519, 0},
		"RSA 4096":    {"RSA 4096", ssh.KeyAlgoRSA, 4096},
		"RSA 2048":    {"RSA 2048", ssh.KeyAlgoRSA, 2048},
		"ECDSA P-256": {"ECDSA P-256", ssh.KeyAlgoECDSA256, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gw := sshGateway(t, sshCreateOK)
			var logs bytes.Buffer
			res, out, err := newTools(gw.URL, &logs).generateSSHKey(context.Background(), callReq("Bearer agent-tok"), generateSSHKeyIn{
				FolderID: "f1", Name: "deploy key", KeyFormat: tc.format, Comment: "deploy@build-01", Username: "deploy",
			})
			if err != nil {
				t.Fatalf("generateSSHKey: %v", err)
			}
			fields := checkCreated(t, gw, tc, out)
			if out.Secret.ID != "s1" || out.Placement == nil || out.Placement.Rule != "REQUESTED" {
				t.Fatalf("out %+v", out)
			}
			checkStoredPair(t, tc, fields, out)
			body, _ := json.Marshal(out)
			if res != nil {
				rb, _ := json.Marshal(res)
				body = append(body, rb...)
			}
			checkNoPrivateKey(t, fields["privateKey"], out.PublicKey, string(body)+logs.String())
		})
	}
}

// checkCreated checks the one create call and returns the fields it
// stored.
func checkCreated(t *testing.T, gw *sshGW, tc keyCase, out generateSSHKeyOut) map[string]string {
	t.Helper()
	n, fields, vars := gw.created()
	if n != 1 || vars["typeId"] != "type-ssh-key" || vars["folderId"] != "f1" || vars["name"] != "deploy key" {
		t.Fatalf("creates=%d vars=%v", n, vars)
	}
	want := tc.format
	if want == "" {
		want = "Ed25519"
	}
	if fields["keyFormat"] != want || fields["username"] != "deploy" || out.KeyFormat != want {
		t.Fatalf("fields keyFormat=%q username=%q out=%q", fields["keyFormat"], fields["username"], out.KeyFormat)
	}
	return fields
}

// checkStoredPair checks that the stored private key is an OpenSSH key of
// the asked type that matches the returned and stored public half.
func checkStoredPair(t *testing.T, tc keyCase, fields map[string]string, out generateSSHKeyOut) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(fields["privateKey"]))
	if err != nil {
		t.Fatalf("stored private key: %v", err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(out.PublicKey))
	if err != nil {
		t.Fatalf("returned public key %q: %v", out.PublicKey, err)
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) || pub.Type() != tc.keyType || comment != "deploy@build-01" {
		t.Fatalf("public key %q (type %s, comment %q) doesn't match the stored key", out.PublicKey, pub.Type(), comment)
	}
	if cp, ok := pub.(ssh.CryptoPublicKey); tc.bits != 0 && (!ok || bitLen(cp) != tc.bits) {
		t.Fatalf("want %d bits", tc.bits)
	}
	if fields["publicKey"] != out.PublicKey {
		t.Fatalf("stored publicKey %q, returned %q", fields["publicKey"], out.PublicKey)
	}
	if out.Fingerprint != ssh.FingerprintSHA256(pub) || !strings.HasPrefix(out.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint %q", out.Fingerprint)
	}
}

// checkNoPrivateKey checks that seen (the result and the logs) holds no
// part of priv. An OpenSSH private key carries its public half in clear, so
// a line that's also in the public key isn't a leak.
func checkNoPrivateKey(t *testing.T, priv, publicKey, seen string) {
	t.Helper()
	if strings.Contains(seen, "PRIVATE KEY") {
		t.Fatal("the private key leaked")
	}
	for _, part := range privateParts(priv) {
		if !strings.Contains(publicKey, part) && strings.Contains(seen, part) {
			t.Fatalf("the private key leaked (%q)", part)
		}
	}
}

// privateParts are the base64 lines of a PEM private key.
func privateParts(pemKey string) []string {
	var out []string
	for _, l := range strings.Split(pemKey, "\n") {
		if l != "" && !strings.HasPrefix(l, "-----") {
			out = append(out, l)
		}
	}
	return out
}

func bitLen(cp ssh.CryptoPublicKey) int {
	type bitter interface{ Size() int }
	if k, ok := cp.CryptoPublicKey().(bitter); ok {
		return k.Size() * 8
	}
	return 0
}

func TestGenerateSSHKeyRefusesATypeWithNoKeyFields(t *testing.T) {
	gw := sshGateway(t, sshCreateOK)
	_, out, err := newTools(gw.URL, nil).generateSSHKey(context.Background(), callReq("Bearer t"), generateSSHKeyIn{
		FolderID: "f1", Name: "n", TypeID: "type-password",
	})
	if err == nil || !strings.Contains(err.Error(), "privateKey") || out.PublicKey != "" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if n, _, _ := gw.created(); n != 0 {
		t.Fatal("a secret was created")
	}
	_, _, err = newTools(gw.URL, nil).generateSSHKey(context.Background(), callReq("Bearer t"), generateSSHKeyIn{
		FolderID: "f1", Name: "n", TypeID: "type-missing",
	})
	if err == nil || !strings.Contains(err.Error(), "type-missing") {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestGenerateSSHKeyRefusesBadInputBeforeTheGateway(t *testing.T) {
	cases := map[string]generateSSHKeyIn{
		"no folder":           {Name: "n"},
		"no name":             {FolderID: "f1"},
		"unknown format":      {FolderID: "f1", Name: "n", KeyFormat: "DSA"},
		"multi-line comment":  {FolderID: "f1", Name: "n", Comment: "a\nb"},
		"long comment":        {FolderID: "f1", Name: "n", Comment: strings.Repeat("c", maxNameLen+1)},
		"control in username": {FolderID: "f1", Name: "n", Username: "a\x00b"},
	}
	for name, in := range cases {
		gw := sshGateway(t, sshCreateOK)
		if _, _, err := newTools(gw.URL, nil).generateSSHKey(context.Background(), callReq("Bearer t"), in); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if n, _, _ := gw.created(); n != 0 {
			t.Errorf("%s: a secret was created", name)
		}
	}
}

func TestGenerateSSHKeyForwardsTheTargetAndAutomation(t *testing.T) {
	gw := sshGateway(t, sshCreateOK)
	_, _, err := newTools(gw.URL, nil).generateSSHKey(context.Background(), callReq("Bearer t"), generateSSHKeyIn{
		FolderID: "f1", Name: "n", TargetID: "tg1", DisableHeartbeat: true, KeepFolder: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, fields, vars := gw.created()
	if vars["targetId"] != "tg1" || vars["disableHeartbeat"] != true || vars["keepFolder"] != true {
		t.Fatalf("vars %v", vars)
	}
	if _, ok := fields["username"]; ok {
		t.Fatal("an empty username was sent")
	}
}

func TestGenerateSSHKeyNeverRelaysAnErrorThatQuotesTheKey(t *testing.T) {
	// A gateway that echoes the stored fields back in its error.
	g := sshGateway(t, "")
	g.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Query, "secretTypes") {
			_, _ = io.WriteString(w, sshTypesReply)
			return
		}
		fs, _ := json.Marshal(req.Variables["fields"])
		msg, _ := json.Marshal("rpc error: code = InvalidArgument desc = bad fields " + string(fs))
		_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":`+string(msg)+`}]}`)
	})
	_, _, err := newTools(g.URL, nil).generateSSHKey(context.Background(), callReq("Bearer t"), generateSSHKeyIn{FolderID: "f1", Name: "n"})
	if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "b3BlbnNzaC1rZXktdjE") {
		t.Fatalf("err = %v", err)
	}
}
