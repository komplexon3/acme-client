package main

import (
	"errors"

	"github.com/komplexon3/acme-client/jose"
)

func (acme *acmeClient) createAccount() error {
	logger := acme.logger.WithField("method", "createAccount")
	if acme.endpoints.NewAccount == "" {
		logger.Error("No new account endpoint")
		return errors.New("NewAccount endpoint not set")
	}

	jwk := jose.GetJWK(*acme.privateKey)

	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
	}
	headers := map[string]interface{}{
		"jwk": jwk,
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
