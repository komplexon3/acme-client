package main

import (
	"encoding/json"
	"errors"
	"io"

	"gopkg.in/square/go-jose.v2"
)

type identifier struct {
	identifierType string `json:"type"`
	value          string `json:"identifier"`
}

type order struct {
	orderURL       string
	status         string // TODO change to enum
	authorizations []authorization
	finalizeURL    string
}

type orderPayload struct {
	identifiers []identifier `json:"identifiers"`
}

type orderMsg struct {
	status        string       `json:"status"`
	identifiers   []identifier `json:"identifiers"`
	authorization []string     `json:"authorizations"`
	finalize      string       `json:"finalize"`
}

func (acme *acmeConfig) createOrder(domains []string) error {
	logger := acme.logger.WithField("method", "createAccount")
	if acme.endpoints.NewOrder == "" {
		logger.Error("No new order endpoint")
		return errors.New("NewOrder endpoint not set")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before creating order.")
		return errors.New("Missing account URL - can't set kid")
	}

	var identifiers []identifier

	for _, domain := range domains {
		identifiers = append(identifiers, identifier{
			identifierType: "dns",
			value:          domain,
		})
	}

	payload := orderPayload{
		identifiers: identifiers,
	}
	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}

	resp, err := acme.doJosePostRequest(acme.endpoints.NewOrder, headers, payload)
	if err != nil {
		logger.Error("Error creating order: ", err)
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error reading response body: ", err)
		return err
	}

	if resp.StatusCode != 201 {
		logger.WithField("ErrorDesc", getErrorDetails(string(body))).Error("Error creating order: ", resp.Status)
		return errors.New("Error creating order: " + resp.Status)
	}

	var orderResponse orderMsg
	if err := json.Unmarshal(body, &orderResponse); err != nil {
		logger.WithError(err).Error("Error unmarshalling order response")
		return err
	}

	var authorizations []authorization
	for _, authorizationString := range orderResponse.authorization {
		authorizations = append(authorizations, authorization{
			authorizationURL: authorizationString,
		})
	}
	order := order{
		status:         orderResponse.status,
		orderURL:       resp.Header.Get("Location"),
		authorizations: authorizations,
		finalizeURL:    orderResponse.finalize,
	}

	acme.orders = append(acme.orders, order)

	return nil
}
