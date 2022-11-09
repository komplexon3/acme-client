package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"gopkg.in/square/go-jose.v2"
)

type challenge struct {
	Type  string `json:"type"`
	Url   string `json:"url"`
	Token string `json:"token"`
}

func computeKeyauthorization(token string, key crypto.PublicKey) string {
	// in params assuming key is an ecdsa key
	jwk := jose.JSONWebKey{Key: key}
	jwkThumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return ""
	}

	return token + "." + base64.RawURLEncoding.EncodeToString(jwkThumbprint)
}

func (acme *acmeClient) registerDNSChallenge(domain string, chal *challenge) error {
	entry := "_acme-challenge." + domain + "."
	challengeString := computeKeyauthorization(chal.Token, acme.privateKey.Public())
	if challengeString == "" {
		return errors.New("Error computing key authorization")
	}
	digest := sha256.Sum256([]byte(challengeString))
	digestString := base64.RawURLEncoding.EncodeToString(digest[:])

	return acme.dnsProvider.AddTXTRecord(entry, digestString)
}

func (acme *acmeClient) deregisterDNSChallenge(domain string) error {
	entry := "_acme-challenge." + domain + "."
	return acme.dnsProvider.DelTXTRecord(entry)
}

func (acme *acmeClient) registerHTTPChallenge(chal *challenge) error {
	challengeString := computeKeyauthorization(chal.Token, acme.privateKey)
	if challengeString == "" {
		return errors.New("Error computing key authorization")
	}

	return acme.httpChallengeProvider.AddChallengePath(chal.Token, challengeString)
}

func (acme *acmeClient) deregisterHTTPChallenge(chal *challenge) error {
	return acme.httpChallengeProvider.DelChallengePath(chal.Token)
}

func (acme *acmeClient) respondToChallenge(chal *challenge) error {
	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}
	payload := map[string]interface{}{}
	_, err := acme.doJosePostRequest(chal.Url, headers, payload)
	return err
}
