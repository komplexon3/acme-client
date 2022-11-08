package main

import (
	"encoding/json"
	"errors"
	"net/http"
)

func (acme *acmeConfig) getAndSetDirectory() error {
	logger := acme.logger.WithField("method", "GetAndSetDirectory")
	if acme.dir == "" {
		return errors.New("Directory URL not set")
	}

	req, err := http.NewRequest("GET", acme.dir, nil)
	if err != nil {
		logger.WithError(err).Error("Error creating request")
		return err
	}

	resp, err := acme.httpClient.Do(req)

	if resp.StatusCode != 200 {
		return errors.New("Directory request returned error" + resp.Status)
	}

	var endpoint acmeEndpoints
	if err := json.NewDecoder(resp.Body).Decode(&endpoint); err != nil {
		logger.WithError(err).Error("Error decoding response")
		return err
	}

	return nil
}
