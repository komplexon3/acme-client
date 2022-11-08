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
	certificateURL string
}

type orderPayload struct {
	identifiers []identifier `json:"identifiers"`
}

type orderMsg struct {
	status        string       `json:"status"`
	identifiers   []identifier `json:"identifiers"`
	authorization []string     `json:"authorizations"`
	finalize      string       `json:"finalize"`
	certificate   string       `json:"certificate"`
}

func (acme *acmeConfig) createOrder(domains []string) (*order, error) {
	logger := acme.logger.WithField("method", "createAccount")
	if acme.endpoints.NewOrder == "" {
		logger.Error("No new order endpoint")
		return nil, errors.New("NewOrder endpoint not set")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before creating order.")
		return nil, errors.New("Missing account URL - can't set kid")
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
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error reading response body: ", err)
		return nil, err
	}

	if resp.StatusCode != 201 {
		logger.WithField("ErrorDesc", getErrorDetails(string(body))).Error("Error creating order: ", resp.Status)
		return nil, errors.New("Error creating order: " + resp.Status)
	}

	var orderResponse orderMsg
	if err := json.Unmarshal(body, &orderResponse); err != nil {
		logger.WithError(err).Error("Error unmarshalling order response")
		return nil, err
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

	return &order, nil
}

func (acme *acmeConfig) finalizeOrder(order *order) (*order, error) {
	logger := acme.logger.WithField("method", "finalizeOrder")

	if order.finalizeURL == "" {
		logger.Error("Something is wrong. No finalize URL for order.")
		return nil, errors.New("Missing finalize URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before finalizing order.")
		return nil, errors.New("Missing account URL - can't set kid")
	}

	csr := "" // TODO figire out how to generate a CSR

	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}
	payload := map[string]interface{}{
		"csr": csr,
	}

	resp, err := acme.doJosePostRequest(order.finalizeURL, headers, payload)
	if err != nil {
		logger.Error("Error finalizing order: ", err)
		return nil, err
	}

	body, err1 := io.ReadAll(resp.Body)
	if err1 != nil {
		logger.Error("Error reading response body: ", err)
		return nil, err
	}

	if resp.StatusCode != 200 || resp.StatusCode != 201 {
		logger.WithField("ErrorDesc", getErrorDetails(string(body))).Error("Error finalizing order: ", resp.Status)
		return nil, errors.New("Error finalizing order: " + resp.Status)
	}

	var orderResponse orderMsg
	if err := json.Unmarshal(body, &orderResponse); err != nil {
		logger.WithError(err).Error("Error unmarshalling order response")
		return nil, err
	}

	order.status = orderResponse.status
	order.certificateURL = orderResponse.certificate

	return order, nil
}

func (acme *acmeConfig) pollUntilReady(order *order, maxRetries int) error {
	logger := acme.logger.WithField("method", "finalizeOrder")

	if order.orderURL == "" {
		logger.Error("Something is wrong. No finalize URL for order.")
		return errors.New("Missing order URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before finalizing order.")
		return errors.New("Missing account URL - can't set kid")
	}

	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}
	payload := map[string]interface{}{}

	for i := 0; i < maxRetries; i++ {
		resp, err := acme.doJosePostRequest(order.finalizeURL, headers, payload)
		if err != nil {
			logger.Error("Error finalizing order: ", err)
			return err
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Error("Error reading response body: ", err)
			return err
		}

		if resp.StatusCode != 200 || resp.StatusCode != 201 {
			logger.WithField("ErrorDesc", getErrorDetails(string(body))).Error("Error finalizing order: ", resp.Status)
			return errors.New("Error finalizing order: " + resp.Status)
		}

		var orderResponse orderMsg
		if err := json.Unmarshal(body, &orderResponse); err != nil {
			logger.WithError(err).Error("Error unmarshalling order response")
			return err
		}

		if orderResponse.status != "pending" {
			logger.Error("Order is not pending. Status: ", orderResponse.status)
			return errors.New("Order not ready to be polled")
		}

		if orderResponse.status == "ready" {
			// the server verified that the authorization is valid
			return nil

		}
	}
	logger.Error("Max retries reached. Order not ready.")
	return errors.New("Max retries reached. Order not ready.")
}
