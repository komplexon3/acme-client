package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/square/go-jose.v2"
)

type authorization struct {
	status           string
	authorizationURL string
	challenges       []challenge
}

type authorizartionMsg struct {
	status     string      `json:"status"`
	challenges []challenge `json:"challenges"`
}

func (acme *acmeClient) getAuthorization(authorizationURL string) (*authorization, error) {
	logger := acme.logger.WithField("method", "getAuthorization")

	if authorizationURL == "" {
		logger.Error("No authorization URL")
		return nil, errors.New("No authorization URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before getting authorization.")
		return nil, errors.New("Missing account URL - can't set kid")
	}

	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}

	// empty payload -> post-as-get
	payload := map[string]interface{}{}

	resp, err := acme.doJosePostRequest(authorizationURL, headers, payload)
	body, err1 := io.ReadAll(resp.Body)
	if err1 != nil {
		logger.Error("Error reading response body: ", err)
		return nil, err
	}

	if err != nil {
		logger.WithField("ErrorDesc", getErrorDetails(string(body))).Error("Error getting authorization: ", err)
		return nil, fmt.Errorf("Error getting authorization: %v", err)
	}

	var authorizationResponse authorizartionMsg
	if err := json.Unmarshal(body, &authorizationResponse); err != nil {
		logger.WithError(err).Error("Error unmarshalling authorization response")
		return nil, fmt.Errorf("Error unmarshalling authorization response: %v", err)
	}

	var auth authorization
	auth.status = authorizationResponse.status
	auth.authorizationURL = authorizationURL
	auth.challenges = authorizationResponse.challenges

	return &auth, nil
}
