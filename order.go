package main

import (
	"encoding/json"
	"errors"
	"io"

	"gopkg.in/square/go-jose.v2"
)

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Order struct {
	orderURL       string
	status         string // TODO change to enum
	authorizations []authorization
	finalizeURL    string
	certificateURL string
}

type orderPayload struct {
	Identifiers []identifier `json:"identifiers"`
}

type orderMsg struct {
	Status        string       `json:"status"`
	Identifiers   []identifier `json:"identifiers"`
	Authorization []string     `json:"authorizations"`
	Finalize      string       `json:"finalize"`
	Certificate   string       `json:"certificate"`
}

func (acme *acmeClient) createOrder(domains []string) (*Order, error) {
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
			Type:  "dns",
			Value: domain,
		})
	}

	payload := orderPayload{
		Identifiers: identifiers,
	}
	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}

	logger.WithField("payload", payload).Info("Creating order for domains: ", domains)

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
	for _, authorizationString := range orderResponse.Authorization {
		authorizations = append(authorizations, authorization{
			authorizationURL: authorizationString,
		})
	}
	order := Order{
		status:         orderResponse.Status,
		orderURL:       resp.Header.Get("Location"),
		authorizations: authorizations,
		finalizeURL:    orderResponse.Finalize,
	}

	return &order, nil
}

func (acme *acmeClient) finalizeOrder(order *Order) (*Order, error) {
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

	order.status = orderResponse.Status
	order.certificateURL = orderResponse.Certificate

	return order, nil
}

func (acme *acmeClient) pollUntilReady(order *Order, maxRetries int) error {
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

		if orderResponse.Status != "pending" {
			logger.Error("Order is not pending. Status: ", orderResponse.Status)
			return errors.New("Order not ready to be polled")
		}

		if orderResponse.Status == "ready" {
			// the server verified that the authorization is valid
			return nil

		}
	}
	logger.Error("Max retries reached. Order not ready.")
	return errors.New("Max retries reached. Order not ready.")
}
