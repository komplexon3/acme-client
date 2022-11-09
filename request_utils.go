package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/komplexon3/acme-client/jose"
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

func (acme *acmeClient) doJosePostRequest(endpoint string, protected map[string]interface{}, payload interface{}) (*http.Response, error) {
	protected["nonce"] = acme.currentNonce
	protected["url"] = endpoint

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

func (acme *acmeClient) josePostRequest(endpoint string, protected map[string]interface{}, payload interface{}) (*http.Request, error) {

	nonce, err := acme.Nonce()
	if err != nil {
		return nil, fmt.Errorf("Error getting nonce: %s", err)
	}

	jwt := jose.JWT{
		Header:  protected,
		Payload: payload,
	}
	signedBody, err := jwt.CreateSignedPayload(*acme.privateKey, nonce)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(signedBody))
	if err != nil {
		return nil, errors.New("Failed to create JOSE POST request: " + err.Error())
	}

	req.Header.Add("Content-Type", "application/jose+json")

	return req, nil
}

func (acmeClient *acmeClient) Nonce() (string, error) {
	if acmeClient.currentNonce != "" {
		return acmeClient.currentNonce, nil
	}

	if err := acmeClient.fetchNewNote(); err != nil {
		return "", err
	}

	nonce := acmeClient.currentNonce
	acmeClient.currentNonce = ""

	return nonce, nil
}
