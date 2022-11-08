package main

import (
	"errors"
	"net/http"
)

func (acme *acmeConfig) fetchNewNote() error {
	logger := acme.logger.WithField("method", "FetchNewNote")
	if acme.endpoints.NewNonce == "" {
		return errors.New("NewNonce endpoint not set")
	}

	req, err := http.NewRequest("HEAD", acme.endpoints.NewNonce, nil)
	if err != nil {
		logger.WithError(err).Error("Error creating request")
		return err
	}

	// nonce could be cached leading to us getting badNonce errors
	req.Header.Add("Cache-Control", "no-store")

	resp, err := acme.httpClient.Do(req)

	if resp.StatusCode != 200 {
		return errors.New("NewNonce endpoint returned " + resp.Status)
	}

	acme.currentNonce = resp.Header.Get("Replay-Nonce")

	return nil
}
