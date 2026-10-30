// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

const (
	toolGenerateSSHKey = "sneakers_generate_ssh_key"
	sshKeyTypeID       = "type-ssh-key"
	defaultKeyFormat   = "Ed25519"
)

// sshKeyFormats are the SSH Key type's keyFormat options, the same four the
// web and the vault's GenerateKeyPair offer.
var sshKeyFormats = []string{"Ed25519", "RSA 4096", "RSA 2048", "ECDSA P-256"}

// The field keys a key-pair type declares, as the web reads them.
const (
	fieldPrivateKey = "privateKey"
	fieldPublicKey  = "publicKey"
	fieldKeyFormat  = "keyFormat"
	fieldUsername   = "username"
)

// --- sneakers_generate_ssh_key ------------------------------------------

type generateSSHKeyIn struct {
	FolderID  string `json:"folderId" jsonschema:"destination folder id"`
	Name      string `json:"name" jsonschema:"name for the new secret"`
	KeyFormat string `json:"keyFormat,omitempty" jsonschema:"Ed25519 (the default), RSA 4096, RSA 2048 or ECDSA P-256"`
	Comment   string `json:"comment,omitempty" jsonschema:"comment at the end of the public key line, such as deploy@build-01"`
	Username  string `json:"username,omitempty" jsonschema:"the account the key signs in as, stored in the username field"`
	TypeID    string `json:"typeId,omitempty" jsonschema:"secret type id; default type-ssh-key. It must declare privateKey and publicKey fields"`
	TargetID  string `json:"targetId,omitempty" jsonschema:"optional target id to associate"`

	DisableRotation  bool `json:"disableRotation,omitempty" jsonschema:"create the secret with rotation turned off"`
	DisableHeartbeat bool `json:"disableHeartbeat,omitempty" jsonschema:"create the secret with heartbeat checks turned off"`
	KeepFolder       bool `json:"keepFolder,omitempty" jsonschema:"store the secret in folderId even when its name or the username names you; without it such a secret goes to your Personal folder"`
}

type generateSSHKeyOut struct {
	Secret      secretSummary `json:"secret"`
	PublicKey   string        `json:"publicKey" jsonschema:"the public key as one authorized_keys line, to install on the hosts the key signs in to"`
	Fingerprint string        `json:"fingerprint" jsonschema:"the public key's SHA-256 fingerprint, as ssh-keygen -l prints it (SHA256:...)"`
	KeyFormat   string        `json:"keyFormat" jsonschema:"the key format generated"`
	Placement   *placement    `json:"placement,omitempty" jsonschema:"where the secret was stored and why"`
}

func checkKeyFormat(f string) error {
	if f == "" || slices.Contains(sshKeyFormats, f) {
		return nil
	}
	return fmt.Errorf("keyFormat must be one of %s", strings.Join(sshKeyFormats, ", "))
}

// checkLine refuses a value that would break the public key line or the
// field it's stored in: no line breaks or other control characters.
func checkLine(name, v string) error {
	if err := checkLen(name, v, maxNameLen, false); err != nil {
		return err
	}
	if strings.ContainsFunc(v, unicode.IsControl) {
		return fmt.Errorf("%s must be one line with no control characters", name)
	}
	return nil
}

// keyPairType checks that the catalog has typeID and that it holds a key
// pair, and reports whether it declares the keyFormat and username fields.
func (t *toolset) keyPairType(ctx context.Context, token, typeID string) (hasFormat, hasUsername bool, err error) {
	types, err := t.gw.ListSecretTypes(ctx, token)
	if err != nil {
		return false, false, err
	}
	i := slices.IndexFunc(types, func(ty gwclient.SecretType) bool { return ty.ID == typeID })
	if i < 0 {
		return false, false, fmt.Errorf("%w: type %s is not in the type catalog", errInvalidInput, typeID)
	}
	has := func(key string) bool {
		return slices.ContainsFunc(types[i].Fields, func(f gwclient.TypeField) bool { return f.Key == key })
	}
	if !has(fieldPrivateKey) || !has(fieldPublicKey) {
		return false, false, fmt.Errorf("%w: type %s has no %s and %s fields, so it holds no key pair; use %s for a password type",
			errInvalidInput, typeID, fieldPrivateKey, fieldPublicKey, toolGenerate)
	}
	return has(fieldKeyFormat), has(fieldUsername), nil
}

func (t *toolset) generateSSHKey(ctx context.Context, req *mcp.CallToolRequest, in generateSSHKeyIn) (*mcp.CallToolResult, generateSSHKeyOut, error) {
	var out generateSSHKeyOut
	format, typeID := in.KeyFormat, in.TypeID
	if format == "" {
		format = defaultKeyFormat
	}
	if typeID == "" {
		typeID = sshKeyTypeID
	}
	err := t.run(req, toolGenerateSSHKey,
		func() error {
			return checkAll(checkLen("folderId", in.FolderID, maxIDLen, true),
				checkLen("name", in.Name, maxNameLen, true),
				checkLen("typeId", in.TypeID, maxIDLen, false),
				checkLen("targetId", in.TargetID, maxIDLen, false),
				checkKeyFormat(in.KeyFormat),
				checkLine("comment", in.Comment),
				checkLine("username", in.Username))
		},
		func(token string) error {
			hasFormat, hasUsername, err := t.keyPairType(ctx, token, typeID)
			if err != nil {
				return err
			}
			priv, pub, err := newKeyPair(format, in.Comment)
			if err != nil {
				return err
			}
			t.log.Debug().Str("tool", toolGenerateSSHKey).Str("format", format).Str("fingerprint", ssh.FingerprintSHA256(pub)).
				Msg("ssh key pair generated")
			line := authorizedLine(pub, in.Comment)
			fields := []gwclient.Field{{Key: fieldPrivateKey, Value: priv}, {Key: fieldPublicKey, Value: line}}
			if hasFormat {
				fields = append(fields, gwclient.Field{Key: fieldKeyFormat, Value: format})
			}
			if in.Username != "" && hasUsername {
				fields = append(fields, gwclient.Field{Key: fieldUsername, Value: in.Username})
			}
			s, err := t.gw.CreateSecret(ctx, token, in.FolderID, typeID, in.Name, fields, in.TargetID,
				gwclient.Automation{DisableRotation: in.DisableRotation, DisableHeartbeat: in.DisableHeartbeat, KeepFolder: in.KeepFolder})
			if err != nil {
				return withoutKey(err, priv)
			}
			out = generateSSHKeyOut{Secret: summaryOf(*s), PublicKey: line, Fingerprint: ssh.FingerprintSHA256(pub),
				KeyFormat: format, Placement: placementOf(s.Placement)}
			return nil
		})
	if err != nil {
		return nil, generateSSHKeyOut{}, err
	}
	return nil, out, nil
}

// withoutKey keeps a gateway error away from the agent when its message
// quotes any part of the private key; it should never, but the agent's
// transcript is exactly where the key must not go.
func withoutKey(err error, priv string) error {
	var ge *gwclient.GraphQLError
	if !errors.As(err, &ge) {
		return err
	}
	msg := ge.Error()
	quoted := strings.Contains(msg, "PRIVATE KEY")
	for _, l := range strings.Split(priv, "\n") {
		quoted = quoted || (l != "" && !strings.HasPrefix(l, "-----") && strings.Contains(msg, l))
	}
	if quoted {
		return &gwclient.GraphQLError{Messages: []string{"the vault refused the new SSH key secret, and its message isn't shown because it quoted the key"}}
	}
	return err
}

// newKeyPair makes a key pair in format with crypto/rand, the same way the
// vault's GenerateKeyPair does: the private key as an unencrypted OpenSSH
// PEM, carrying comment. The private key must never be logged.
func newKeyPair(format, comment string) (privatePEM string, pub ssh.PublicKey, err error) {
	var key any
	switch format {
	case "Ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "RSA 4096":
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case "RSA 2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ECDSA P-256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return "", nil, fmt.Errorf("%w: unsupported key format %q", errInvalidInput, format)
	}
	if err != nil {
		return "", nil, fmt.Errorf("generate a %s key: %w", format, err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return "", nil, fmt.Errorf("derive the %s public key: %w", format, err)
	}
	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return "", nil, fmt.Errorf("encode the %s private key: %w", format, err)
	}
	return string(pem.EncodeToMemory(block)), signer.PublicKey(), nil
}

// authorizedLine is pub as one authorized_keys line, with comment.
func authorizedLine(pub ssh.PublicKey, comment string) string {
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}

func registerSSHKeyTool(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolGenerateSSHKey,
		Description: "Generate an SSH key pair on the Sneakers side and store it as a new SSH Key secret, so the private " +
			"key never passes through this session. keyFormat is Ed25519 (the default), RSA 4096, RSA 2048 or ECDSA " +
			"P-256; comment ends the public key line; username fills the username field. Returns only the public key " +
			"line and its SHA-256 fingerprint, to install on the hosts the key signs in to; the private key is never " +
			"returned, and a person reads it on the web or uses it with sneakers-run. The secret is the same kind the " +
			"web's key pair generator makes (privateKey, publicKey, keyFormat and username fields). Requires author " +
			"access to the folder; audited as a secret creation by the token's user or service account. A typeId " +
			"other than type-ssh-key must declare privateKey and publicKey fields; a type without them is refused. " +
			"Placement and keepFolder work as in " + toolCreate + ".",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.generateSSHKey)
}
