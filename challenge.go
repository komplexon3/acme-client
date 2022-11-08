package main

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"

	"gopkg.in/square/go-jose.v2"
)

type challenge struct {
	challengeType string `json:"type"`
	url           string `json:"url"`
	token         string `json:"token"`
}

func computeKeyauthorization(token string, key *ecdsa.PrivateKey) string {
	// in params assuming key is an ecdsa key
	jwk := jose.JSONWebKey{Key: key.PublicKey}
	jwkThumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return ""
	}

	return token + "." + base64.RawURLEncoding.EncodeToString(jwkThumbprint)
}

func (acme *acmeClient) registerDNSChallenge(domain string, chal *challenge) error {
	entry := "_acme-challenge." + domain
	challengeString := computeKeyauthorization(chal.token, acme.privateKey)
	if challengeString == "" {
		return errors.New("Error computing key authorization")
	}

	return acme.dnsProvider.AddTXTRecord(entry, challengeString)
}

func (acme *acmeClient) deregisterDNSChallenge(domain string) error {
	entry := "_acme-challenge." + domain
	return acme.dnsProvider.DelTXTRecord(entry)
}

func (acme *acmeClient) registerHTTPChallenge(chal *challenge) error {
	challengeString := computeKeyauthorization(chal.token, acme.privateKey)
	if challengeString == "" {
		return errors.New("Error computing key authorization")
	}

	return acme.httpChallengeProvider.AddChallengePath(chal.token, challengeString)
}

func (acme *acmeClient) deregisterHTTPChallenge(chal *challenge) error {
	return acme.httpChallengeProvider.DelChallengePath(chal.token)
}
