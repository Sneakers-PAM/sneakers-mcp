// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

// keyring is a store that may not be running, such as the Secret Service,
// which a desktop session starts and a headless box usually doesn't have.
type keyring interface {
	Store
	Available() bool
}

// fallbackStore keeps tokens in the keyring when one is running, and in
// files only this user can read when none is, so login works on a desktop
// and on a headless box alike.
type fallbackStore struct {
	keyring keyring
	file    Store
}

func (s fallbackStore) Get(account string) (string, bool, error) {
	if s.keyring.Available() {
		if token, ok, err := s.keyring.Get(account); err != nil || ok {
			return token, ok, err
		}
	}
	// A box signed in while headless keeps that token in a file.
	return s.file.Get(account)
}

func (s fallbackStore) Set(account, token string) error {
	if !s.keyring.Available() {
		return s.file.Set(account, token)
	}
	if err := s.keyring.Set(account, token); err != nil {
		return err
	}
	// An earlier headless sign-in's file would otherwise outlive this token.
	return s.file.Delete(account)
}

func (s fallbackStore) Delete(account string) error {
	if s.keyring.Available() {
		if err := s.keyring.Delete(account); err != nil {
			return err
		}
	}
	return s.file.Delete(account)
}

func (s fallbackStore) Where(account string) string {
	if s.keyring.Available() {
		return s.keyring.Where(account)
	}
	return s.file.Where(account)
}
