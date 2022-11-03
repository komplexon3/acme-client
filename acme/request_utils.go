package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

func (acme *acmeConfig) doJosePostRequest(endpoint string, protected map[jose.HeaderKey]interface{}, payload interface{}) (*http.Response, error) {
	protected[jose.HeaderKey("url")] = endpoint
	req, err := acme.josePostRequest(endpoint, protected, payload)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.New("Error sending request: " + err.Error())
	}

	return resp, nil
}

func (acme *acmeConfig) josePostRequest(endpoint string, protected map[jose.HeaderKey]interface{}, payload interface{}) (*http.Request, error) {
	var body []byte
	if body, err := json.Marshal(payload); err != nil {
		return nil, errors.New("Error marshalling payload " + err.Error())
	}

	signedBody, err := acme.signPayload(body, protected, acme.privateKey)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer([]byte(signedBody.FullSerialize())))
	if err != nil {
		return nil, errors.New("Failed to create JOSE POST request: " + err.Error())
	}

	req.Header.Add("Content-Type", "application/jose+json")

	return req, nil
}

// TODO: write with your own JOSE implementation
func (acme *acmeConfig) signPayload(payload []byte, headers map[jose.HeaderKey]interface{}, privateKey *ecdsa.PrivateKey) (*jose.JSONWebSignature, error) {
	alg := jose.ES256 // no clue but using ES256 bc that's in the RFC examples
	NS := NonceSource{acmeConf: acme}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: privateKey}, &jose.SignerOptions{
		NonceSource:  &NS,
		ExtraHeaders: headers,
	})

	if err != nil {
		return nil, errors.New("Error creating signer: " + err.Error())
	}

	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return nil, errors.New("Error creating signer: " + err.Error())
	}

	return signedPayload, nil
}

// comply to jose.NoneSource

type NonceSource struct {
	acmeConf *acmeConfig
}

func (ns *NonceSource) Nonce() (string, error) {
	if ns.acmeConf.currentNonce != "" {
		return ns.acmeConf.currentNonce, nil
	}

	if err := ns.acmeConf.fetchNewNote(); err != nil {
		return "", err
	}

	return ns.acmeConf.currentNonce, nil
}
