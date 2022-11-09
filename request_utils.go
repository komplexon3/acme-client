package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"gopkg.in/square/go-jose.v2"
)

func setupClient(certFilePath string, proxy string) (*http.Client, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return nil, errors.New("Failed to append " + certFilePath + " to RootCAs: " + err.Error())
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, errors.New("Failed t append " + certFilePath + " to RootCAs")
	}
	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: proxy != "",
		RootCAs:            rootCAs,
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, errors.New("Failed to parse proxy URL: " + err.Error())
		}
		client.Transport = &http.Transport{TLSClientConfig: config, Proxy: http.ProxyURL(proxyURL)}
	}

	return client, nil
}

func (acme *acmeClient) doJosePostRequest(endpoint string, protected map[jose.HeaderKey]interface{}, payload interface{}) (*http.Response, error) {
	protected[jose.HeaderKey("url")] = endpoint
	req, err := acme.josePostRequest(endpoint, protected, payload)
	if err != nil {
		return nil, err
	}

	resp, err := acme.httpClient.Do(req)
	if err == nil {
		acme.currentNonce = resp.Header.Get("Replay-Nonce")
	}

	return resp, err
}

func (acme *acmeClient) josePostRequest(endpoint string, protected map[jose.HeaderKey]interface{}, payload interface{}) (*http.Request, error) {
	var body []byte
	var err error
	if payload == nil {
		body = []byte{}
	} else if body, err = json.Marshal(payload); err != nil {
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
func (acme *acmeClient) signPayload(payload []byte, headers map[jose.HeaderKey]interface{}, privateKey *ecdsa.PrivateKey) (*jose.JSONWebSignature, error) {
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
	acmeConf *acmeClient
}

func (ns *NonceSource) Nonce() (string, error) {
	if ns.acmeConf.currentNonce != "" {
		return ns.acmeConf.currentNonce, nil
	}

	if err := ns.acmeConf.fetchNewNote(); err != nil {
		return "", err
	}

	nonce := ns.acmeConf.currentNonce
	ns.acmeConf.currentNonce = ""

	return nonce, nil
}
