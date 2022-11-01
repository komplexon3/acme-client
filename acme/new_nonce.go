package main

import (
	"errors"
	"net/http"
)

func (acme *acmeConfig) FetchNewNote() error {
	if acme.endpoints.NewNonce == "" {
		return errors.New("NewNonce endpoint not set")
	}

	resp, err := http.Head(acme.endpoints.NewNonce)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("NewNonce endpoint returned " + resp.Status)
	}

	acme.currentNonce = resp.Header.Get("Replay-Nonce")

	return nil
}
