package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

type authorization struct {
	status           string
	authorizationURL string
	identifier       identifier
	challenges       []challenge
}

type authorizartionMsg struct {
	Status     string      `json:"status"`
	Challenges []challenge `json:"challenges"`
	Identifier identifier  `json:"identifier"`
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

	headers := map[string]interface{}{
		"kid": acme.accountURL,
	}

	// empty payload -> post-as-get

	resp, err := acme.doJosePostRequest(authorizationURL, headers, nil)
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
	auth.status = authorizationResponse.Status
	auth.authorizationURL = authorizationURL
	auth.challenges = authorizationResponse.Challenges
	auth.identifier = authorizationResponse.Identifier

	return &auth, nil
}

func (acme *acmeClient) registerChallenge(auth *authorization, challengeType ChallengeType) (*challenge, error) {
	logger := acme.logger.WithField("method", "registerChallenge")

	chalType := func() string {
		switch challengeType {
		case DNS01:
			return "dns-01"
		case HTTP01:
			return "http-01"
		default:
			logger.Fatal("Challenge type must be dns01 or http01")
			return ""
		}
	}()

	for _, chal := range auth.challenges {
		if chal.Type == chalType {
			if chal.Type == "dns-01" {
				if err := acme.registerDNSChallenge(auth.identifier.Value, &chal); err != nil {
					logger.WithError(err).Error("Error registering DNS challenge")
					return nil, err
				} else {
					return &chal, nil
				}
			} else if chal.Type == "http-01" {
				if err := acme.registerHTTPChallenge(&chal); err != nil {
					logger.WithError(err).Error("Error registering HTTP challenge")
					return nil, err
				} else {
					return &chal, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("No challenge of type %s found", chalType)
}

func (acmeClient *acmeClient) pollAuthorization(auth *authorization, maxPoll int) error {
	logger := acmeClient.logger.WithField("method", "pollAuthorization")

	valid := false
	i := 0
	for !valid && i < maxPoll {
		_auth, err := acmeClient.getAuthorization(auth.authorizationURL)
		if err != nil {
			logger.WithError(err).Error("Error getting authorization")
			return err
		}

		auth.status = _auth.status
		if auth.status == "valid" {
			valid = true
			return nil
		}
		time.Sleep(time.Second)
		i++
	}
	return fmt.Errorf("Authorization not valid after %d polls", maxPoll)
}
