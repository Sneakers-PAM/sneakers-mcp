// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// vaultCatalogue holds the SELECT fields of the vault's built-in type
// catalogue, vendored at the commit in vault-catalogue.env
// (scripts/vault-catalogue-fetch.sh).
//
//go:embed vault-select-fields.json
var vaultCatalogue []byte

// selectOptionsHint lists every SELECT field of the built-in types with its
// options, for the write tools' descriptions. It panics on a malformed
// vendored file, which the tests catch before it ships.
func selectOptionsHint() string {
	var cat struct {
		Types []struct {
			ID     string `json:"id"`
			Fields []struct {
				Key      string   `json:"key"`
				Kind     string   `json:"kind"`
				Required bool     `json:"required"`
				Options  []string `json:"options"`
			} `json:"fields"`
		} `json:"types"`
	}
	if err := json.Unmarshal(vaultCatalogue, &cat); err != nil {
		panic("tools: vendored vault catalogue: " + err.Error())
	}
	var entries []string
	for _, ty := range cat.Types {
		for _, f := range ty.Fields {
			if f.Kind != "SELECT" || len(f.Options) == 0 {
				continue
			}
			e := ty.ID + " " + f.Key + ": " + strings.Join(f.Options, " | ")
			if f.Required {
				e += " (required)"
			}
			entries = append(entries, e)
		}
	}
	return "A SELECT field takes one of its type's options; any other value is refused, naming the field and " +
		"listing the options, and a different letter case is stored as the option. The built-in SELECT fields " +
		"(typeId field: options) are " + strings.Join(entries, "; ") + ". A type added by an admin may have " +
		"SELECT fields of its own."
}
