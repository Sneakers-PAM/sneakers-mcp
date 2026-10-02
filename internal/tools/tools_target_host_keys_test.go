// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// genHostKeyLine builds an ed25519 public key in authorized_keys form from a
// key generated per run, and its OpenSSH SHA256 fingerprint (the unpadded
// base64 of the SHA-256 of the key blob).
func genHostKeyLine(t *testing.T) (line, fp string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	for _, part := range [][]byte{[]byte("ssh-ed25519"), pub} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(part)))
		blob = append(blob, part...)
	}
	sum := sha256.Sum256(blob)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " web-01", "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func TestListTargetsToolShowsHostKeyFingerprints(t *testing.T) {
	line, fp := genHostKeyLine(t)
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"targetsForPrincipal": []map[string]any{
		{"id": "t2", "name": "web-01", "hostname": "web-01.example.org", "connectionId": "conn-ssh", "ownerUserId": "", "sshHostKeys": []string{line}},
		{"id": "t3", "name": "web-02", "hostname": "web-02.example.org", "connectionId": "conn-ssh", "ownerUserId": "", "sshHostKeys": []string{}},
	}}})
	gw := fakeGateway(t, string(body))
	_, out, err := newTools(gw.URL, nil).listTargets(context.Background(), callReq("Bearer t"), listTargetsIn{})
	if err != nil || len(out.Targets) != 2 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if got := out.Targets[0].HostKeyFingerprints; len(got) != 1 || got[0] != fp {
		t.Fatalf("fingerprints = %q, want [%s]", got, fp)
	}
	if got := out.Targets[1].HostKeyFingerprints; got == nil || len(got) != 0 {
		t.Fatalf("unpinned target fingerprints = %#v, want []", got)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), strings.Fields(line)[1]) {
		t.Fatalf("tool output carries the key itself: %s", raw)
	}
}

func TestSaveTargetToolForwardsHostKeys(t *testing.T) {
	line, fp := genHostKeyLine(t)
	resp, _ := json.Marshal(map[string]any{"data": map[string]any{"saveTargetForPrincipal": map[string]any{
		"id": "t9", "name": "web-01", "hostname": "web-01.example.org", "connectionId": "conn-ssh", "ownerUserId": "u-ada", "sshHostKeys": []string{line},
	}}})
	gw := fakeGateway(t, string(resp))
	ts := newTools(gw.URL, nil)
	in := saveTargetIn{ID: "t9", Name: "web-01", Hostname: "web-01.example.org", ConnectionID: "conn-ssh"}
	sent := func() (any, bool) {
		vars, _ := gw.vars.Load().(map[string]any)
		input, _ := vars["input"].(map[string]any)
		v, ok := input["sshHostKeys"]
		return v, ok
	}

	in.HostKeys = []string{line}
	_, out, err := ts.saveTarget(context.Background(), callReq("Bearer t"), in)
	if v, _ := sent(); err != nil || len(v.([]any)) != 1 || v.([]any)[0] != line {
		t.Fatalf("sent %#v err=%v", v, err)
	}
	if len(out.Target.HostKeyFingerprints) != 1 || out.Target.HostKeyFingerprints[0] != fp {
		t.Fatalf("returned fingerprints = %q", out.Target.HostKeyFingerprints)
	}

	in.HostKeys = nil
	if _, _, err := ts.saveTarget(context.Background(), callReq("Bearer t"), in); err != nil {
		t.Fatal(err)
	}
	if v, ok := sent(); ok {
		t.Fatalf("omitted hostKeys sent %#v; it must be left out to keep the pins", v)
	}

	in.HostKeys = []string{}
	if _, _, err := ts.saveTarget(context.Background(), callReq("Bearer t"), in); err != nil {
		t.Fatal(err)
	}
	if v, ok := sent(); !ok || len(v.([]any)) != 0 {
		t.Fatalf("hostKeys [] sent %#v, want []", v)
	}
}

// pemHeader is assembled so no private-key marker appears whole in the source.
const pemHeader = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"

func TestSaveTargetToolRefusesBadHostKeysLocally(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"saveTargetForPrincipal":{"id":"t9"}}}`)
	ts := newTools(gw.URL, nil)
	line, _ := genHostKeyLine(t)
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = line
	}
	for name, keys := range map[string][]string{
		"private key": {pemHeader + "\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH " + "PRIVATE KEY-----"},
		"empty":       {"  "},
		"too long":    {"ssh-ed25519 " + strings.Repeat("A", 9000)},
		"too many":    tooMany,
	} {
		_, _, err := ts.saveTarget(context.Background(), callReq("Bearer t"), saveTargetIn{
			Name: "web-01", Hostname: "web-01.example.org", ConnectionID: "conn-ssh", HostKeys: keys,
		})
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), "b3BlbnNzaC") {
			t.Errorf("%s: error echoes the entry: %v", name, err)
		}
	}
	if gw.calls.Load() != 0 {
		t.Fatal("a refused host key reached the gateway")
	}
}
