package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
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
	identifiers    []identifier
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
	headers := map[string]interface{}{
		"kid": acme.accountURL,
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
		identifiers:    orderResponse.Identifiers,
	}

	return &order, nil
}

func (acme *acmeClient) finalizeOrder(order *Order, key *ecdsa.PrivateKey) error {
	logger := acme.logger.WithField("method", "finalizeOrder")

	if order.finalizeURL == "" {
		logger.Error("Something is wrong. No finalize URL for order.")
		return errors.New("Missing finalize URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before finalizing order.")
		return errors.New("Missing account URL - can't set kid")
	}

	// we only create dns identifiers so we can assume there are no other types
	DNSNames := make([]string, len(order.identifiers))
	for i, identifier := range order.identifiers {
		DNSNames[i] = identifier.Value
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: DNSNames,
	}, key)

	if err != nil {
		logger.WithError(err).Error("Error creating CSR")
		return err
	}

	csrEncoded := base64.RawURLEncoding.EncodeToString(csr)

	headers := map[string]interface{}{
		"kid": acme.accountURL,
	}
	payload := map[string]interface{}{
		"csr": csrEncoded,
	}

	resp, err := acme.doJosePostRequest(order.finalizeURL, headers, payload)
	if err != nil {
		logger.Error("Error finalizing order: ", err)
		return err
	}

	body, err1 := io.ReadAll(resp.Body)
	if err1 != nil {
		logger.Error("Error reading response body: ", err)
		return err
	}

	var orderResponse orderMsg
	if err := json.Unmarshal(body, &orderResponse); err != nil {
		logger.WithError(err).Error("Error unmarshalling order response")
		return err
	}

	order.status = orderResponse.Status

	return nil
}

func (acme *acmeClient) pollUntilReady(order *Order, maxRetries int) error {
	logger := acme.logger.WithField("method", "poll until ready")

	if order.orderURL == "" {
		logger.Error("Something is wrong. No finalize URL for order.")
		return errors.New("Missing order URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before finalizing order.")
		return errors.New("Missing account URL - can't set kid")
	}

	headers := map[string]interface{}{
		"kid": acme.accountURL,
	}

	for i := 0; i < maxRetries; i++ {
		resp, err := acme.doJosePostRequest(order.orderURL, headers, nil)
		if err != nil {
			logger.Error("Error polling order: ", err)
			return err
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Error("Error reading response body: ", err)
			return err
		}

		var orderResponse orderMsg
		if err := json.Unmarshal(body, &orderResponse); err != nil {
			logger.WithError(err).Error("Error unmarshalling order response")
			return err
		}

		if orderResponse.Status == "valid" {
			// the server verified that the authorization is valid
			order.status = orderResponse.Status
			order.certificateURL = orderResponse.Certificate
			return nil
		}

		if orderResponse.Status != "processing" {
			return errors.New("Order is not processing. Status: " + orderResponse.Status)
		}
		time.Sleep(time.Second)
	}
	logger.Error("Max retries reached. Order not ready.")
	return errors.New("Max retries reached. Order not ready.")
}
