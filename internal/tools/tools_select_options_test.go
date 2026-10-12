// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The create, generate and update tools list every SELECT field's options from
// the vendored vault catalogue, and a vault refusal of a value reaches the
// agent with the field and the allowed values.

type selectField struct {
	typeID, key string
	options     []string
}

// vendoredSelects reads the SELECT fields straight from the vendored file,
// independently of the code under test.
func vendoredSelects(t *testing.T) []selectField {
	t.Helper()
	raw, err := os.ReadFile("vault-select-fields.json")
	if err != nil {
		t.Fatalf("read vendored catalogue: %v", err)
	}
	var cat struct {
		Types []struct {
			ID     string `json:"id"`
			Fields []struct {
				Key     string   `json:"key"`
				Kind    string   `json:"kind"`
				Options []string `json:"options"`
			} `json:"fields"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatalf("decode catalogue: %v", err)
	}
	var sels []selectField
	for _, ty := range cat.Types {
		for _, f := range ty.Fields {
			if f.Kind == "SELECT" && len(f.Options) > 0 {
				sels = append(sels, selectField{ty.ID, f.Key, f.Options})
			}
		}
	}
	return sels
}

func TestWriteToolDescriptionsListEverySelectOption(t *testing.T) {
	sels := vendoredSelects(t)
	if len(sels) < 4 {
		t.Fatalf("catalogue has %d SELECT fields, want at least 4 (keyFormat, scheme, engine, logonFormat)", len(sels))
	}
	seen := map[string]bool{}
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolCreate && tl.Name != toolGenerate && tl.Name != toolUpdate {
			continue
		}
		seen[tl.Name] = true
		for _, s := range sels {
			entry := s.typeID + " " + s.key + ": " + strings.Join(s.options, " | ")
			if !strings.Contains(tl.Description, entry) {
				t.Errorf("%s description lacks %q", tl.Name, entry)
			}
		}
		if !strings.Contains(tl.Description, "refused") {
			t.Errorf("%s description does not say other values are refused", tl.Name)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("found %d of the 3 write tools", len(seen))
	}
}

func TestCreateRelaysTheVaultSelectRefusal(t *testing.T) {
	gw := fakeGateway(t, `{"errors":[{"message":"rpc error: code = InvalidArgument desc = field \"engine\" must be one of: \"PostgreSQL\", \"MySQL / MariaDB\", \"SQL Server\", \"Oracle\", \"MongoDB\", \"Other\"",`+
		`"extensions":{"code":"INVALID_ARGUMENT","reason":"FIELD_VALUE_NOT_ALLOWED","domain":"sneakers.vault","metadata":{"field":"engine","allowed":"PostgreSQL|MySQL / MariaDB|SQL Server|Oracle|MongoDB|Other"}}}],"data":null}`)

	_, _, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer agent-tok"), createSecretIn{
		FolderID: "f1", TypeID: "type-database-account", Name: "db",
		Fields: []fieldIn{{Key: "engine", Value: "postgres"}, {Key: "server", Value: "db.example.org"}},
	})
	if err == nil {
		t.Fatal("createSecret succeeded, want the vault's refusal")
	}
	for _, want := range []string{`field "engine" must be one of`, `"PostgreSQL"`, `"MongoDB"`, `"Other"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
}
