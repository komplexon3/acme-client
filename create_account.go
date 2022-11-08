package main

import (
	"errors"

	"gopkg.in/square/go-jose.v2"
)

func (acme *acmeConfig) createAccount() error {
	logger := acme.logger.WithField("method", "createAccount")
	if acme.endpoints.NewAccount == "" {
		logger.Error("No new account endpoint")
		return errors.New("NewAccount endpoint not set")
	}

	jwk := &jose.JSONWebKey{Key: acme.privateKey.Public()}

	payload := map[string]interface{}{}
	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("jwk"): jwk,
	}

	resp, err := acme.doJosePostRequest(acme.endpoints.NewAccount, headers, payload)
	if err != nil {
		logger.Error("Error creating account: ", err)
		return err
	}

	if resp.StatusCode != 201 {
		logger.Error("Error creating account: ", resp.Status)
		return errors.New("Error creating account: " + resp.Status)
	}

	// save the account URL
	acme.accountURL = resp.Header.Get("Location")
	return nil
}
