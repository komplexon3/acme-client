package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
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

func (acme *acmeClient) getAuthorization(authorizationURL string) (*authorization, int, error) {
	logger := acme.logger.WithField("method", "getAuthorization")
	retryAfter := 0

	if authorizationURL == "" {
		logger.Error("No authorization URL")
		return nil, retryAfter, errors.New("No authorization URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before getting authorization.")
		return nil, retryAfter, errors.New("Missing account URL - can't set kid")
	}

	headers := map[string]interface{}{
		"kid": acme.accountURL,
	}

	// empty payload -> post-as-get

	resp, err := acme.doJosePostRequest(authorizationURL, headers, nil)
	body, err1 := io.ReadAll(resp.Body)
	if err1 != nil {
		logger.Error("Error reading response body: ", err)
		return nil, retryAfter, err
	}

	if err != nil {
		logger.WithField("ErrorDesc", getErrorDetails(string(body))).Error("Error getting authorization: ", err)
		return nil, retryAfter, fmt.Errorf("Error getting authorization: %v", err)
	}

	var authorizationResponse authorizartionMsg
	if err := json.Unmarshal(body, &authorizationResponse); err != nil {
		logger.WithError(err).Error("Error unmarshalling authorization response")
		return nil, retryAfter, fmt.Errorf("Error unmarshalling authorization response: %v", err)
	}

	// check retry after
	if retryAfterHeader := resp.Header.Get("Retry-After"); retryAfterHeader != "" {
		retryAfter, err = strconv.Atoi(retryAfterHeader)
		if err != nil {
			logger.WithError(err).Info("Error parsing Retry-After header")
			retryAfter = 0
		}
	}

	var auth authorization
	auth.status = authorizationResponse.Status
	auth.authorizationURL = authorizationURL
	auth.challenges = authorizationResponse.Challenges
	auth.identifier = authorizationResponse.Identifier

	return &auth, retryAfter, nil
}

func (acme *acmeClient) registerChallenge(auth *authorization, challengeType ChallengeType) (*challenge, chan bool, error) {
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
				if tripwire, err := acme.registerDNSChallenge(auth.identifier.Value, &chal); err != nil {
					logger.WithError(err).Error("Error registering DNS challenge")
					return nil, nil, err
				} else {
					return &chal, tripwire, nil
				}
			} else if chal.Type == "http-01" {
				if tripwire, err := acme.registerHTTPChallenge(&chal); err != nil {
					logger.WithError(err).Error("Error registering HTTP challenge")
					return nil, nil, err
				} else {
					return &chal, tripwire, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("No challenge of type %s found", chalType)
}

func (acmeClient *acmeClient) pollAuthorization(auth *authorization, maxPoll int) error {
	logger := acmeClient.logger.WithField("method", "pollAuthorization")

	valid := false
	i := 0
	for !valid && i < maxPoll {
		_auth, retryAfter, err := acmeClient.getAuthorization(auth.authorizationURL)
		if err != nil {
			logger.WithError(err).Error("Error getting authorization")
			return err
		}

		auth.status = _auth.status
		if auth.status == "valid" {
			valid = true
			return nil
		}
		if retryAfter == 0 {
			retryAfter = 1
		}
		time.Sleep(time.Duration(retryAfter) * time.Second)
		i++
	}
	return fmt.Errorf("Authorization not valid after %d polls", maxPoll)
}
