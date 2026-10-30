// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileStore keeps each gateway's token in its own file in dir, readable by
// this user only: the store on a Linux box with no keyring running.
func FileStore(dir string) Store { return fileStore{dir: dir} }

type fileStore struct{ dir string }

func (f fileStore) path(account string) (string, error) {
	if !safeAccount.MatchString(account) {
		return "", fmt.Errorf("token file: %q isn't a gateway host this store takes", account)
	}
	return filepath.Join(f.dir, "token-"+account), nil
}

func (f fileStore) Get(account string) (string, bool, error) {
	path, err := f.path(account)
	if err != nil {
		return "", false, err
	}
	file, err := os.Open(path) // #nosec G304 -- the store's own folder and a checked host name
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("token file: %w", err)
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil {
		return "", false, fmt.Errorf("token file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", false, fmt.Errorf("token file %s can be read by others: chmod 600 it, or run login again", path)
	}
	b, err := io.ReadAll(io.LimitReader(file, 256))
	if err != nil {
		return "", false, fmt.Errorf("token file: %w", err)
	}
	token := strings.TrimRight(string(b), "\n")
	if !personalToken.MatchString(token) {
		return "", false, fmt.Errorf("token file %s doesn't hold a personal token: run login again", path)
	}
	return token, true, nil
}

func (f fileStore) Set(account, token string) error {
	path, err := f.path(account)
	if err != nil {
		return err
	}
	if !personalToken.MatchString(token) {
		return errors.New("token file: only a personal token is stored")
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	// Written whole to a new 0600 file and renamed over the old one, so the
	// token is never in a file others can read, nor half written.
	tmp, err := os.CreateTemp(f.dir, ".token-*")
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	return nil
}

func (f fileStore) Delete(account string) error {
	path, err := f.path(account)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("token file: %w", err)
	}
	return nil
}

func (f fileStore) Where(account string) string {
	path, err := f.path(account)
	if err != nil {
		return f.dir
	}
	return path
}
