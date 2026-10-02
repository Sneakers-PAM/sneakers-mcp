// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"sort"
	"strings"
)

const maskText = "********"

// masker rewrites a stream so the secret, and the encodings a program is
// likely to echo it in, never reach the terminal or a log.
type masker struct {
	w        io.Writer
	patterns [][]byte
	hold     int
	buf      []byte
}

func newMasker(w io.Writer, value string) *masker {
	m := &masker{w: w}
	if value == "" {
		return m
	}
	b := []byte(value)
	seen := map[string]bool{}
	for _, p := range []string{
		value,
		base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
		url.QueryEscape(value), url.PathEscape(value),
	} {
		if !seen[p] {
			seen[p] = true
			m.patterns = append(m.patterns, []byte(p))
		}
	}
	// Longest first so a padded encoding wins over its unpadded prefix.
	sort.Slice(m.patterns, func(i, j int) bool { return len(m.patterns[i]) > len(m.patterns[j]) })
	m.hold = len(m.patterns[0]) - 1
	return m
}

func (m *masker) Write(p []byte) (int, error) {
	if len(m.patterns) == 0 {
		return m.w.Write(p)
	}
	m.buf = append(m.buf, p...)
	if err := m.drain(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes the tail held back in case a match straddled two writes.
func (m *masker) Close() error {
	return m.drain(true)
}

func (m *masker) drain(final bool) error {
	for {
		at, n := -1, 0
		for _, pat := range m.patterns {
			if i := bytes.Index(m.buf, pat); i >= 0 && (at < 0 || i < at) {
				at, n = i, len(pat)
			}
		}
		if at < 0 {
			break
		}
		if _, err := m.w.Write(append(append([]byte{}, m.buf[:at]...), maskText...)); err != nil {
			return err
		}
		m.buf = m.buf[at+n:]
	}
	keep := m.hold
	if final {
		keep = 0
	}
	if cut := len(m.buf) - keep; cut > 0 {
		if _, err := m.w.Write(m.buf[:cut]); err != nil {
			return err
		}
		m.buf = append([]byte{}, m.buf[cut:]...)
	}
	return nil
}
