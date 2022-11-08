package main

import (
	"errors"
	"io"

	"gopkg.in/square/go-jose.v2"
)

type certificate struct {
	certificate string
}

func (acme *acmeClient) getCertificate(certificateURL string) (*certificate, error) {
	/*
			 POST /acme/cert/mAt3xBGaobw HTTP/1.1
		   Host: example.com
		   Content-Type: application/jose+json
		   Accept: application/pem-certificate-chain

		   {
		     "protected": base64url({
		       "alg": "ES256",
		       "kid": "https://example.com/acme/acct/evOfKhNU60wg",
		       "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
		       "url": "https://example.com/acme/cert/mAt3xBGaobw"
		     }),
		     "payload": "",
		     "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
		   }

		   HTTP/1.1 200 OK
		   Content-Type: application/pem-certificate-chain
		   Link: <https://example.com/acme/directory>;rel="index"

		   -----BEGIN CERTIFICATE-----
		   [End-entity certificate contents]
		   -----END CERTIFICATE-----
		   -----BEGIN CERTIFICATE-----
		   [Issuer certificate contents]
		   -----END CERTIFICATE-----
		   -----BEGIN CERTIFICATE-----
		   [Other certificate contents]
		   -----END CERTIFICATE-----
	*/

	logger := acme.logger.WithField("method", "getCertificate")

	if certificateURL == "" {
		logger.Error("No certificate URL")
		return nil, errors.New("No certificate URL")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before getting certificate.")
		return nil, errors.New("Missing account URL - can't set kid")
	}

	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}

	payload := map[string]interface{}{}

	req, err := acme.josePostRequest(certificateURL, headers, payload)
	if err != nil {
		logger.Error("Error creating certificate request: ", err)
		return nil, err
	}

	req.Header.Set("Accept", "application/pem-certificate-chain")
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := acme.httpClient.Do(req)
	if err != nil {
		logger.Error("Error getting certificate: ", err)
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error reading response body: ", err)
		return nil, err
	}

	return &certificate{
		certificate: string(body),
	}, nil
}

func (acme *acmeClient) revokeCertificate(certificate *certificate) error {
	/*
			 POST /acme/revoke-cert HTTP/1.1
		   Host: example.com
		   Content-Type: application/jose+json

		   {
		     "protected": base64url({
		       "alg": "ES256",
		       "kid": "https://example.com/acme/acct/evOfKhNU60wg",
		       "nonce": "JHb54aT_KTXBWQOzGYkt9A",
		       "url": "https://example.com/acme/revoke-cert"
		     }),
		     "payload": base64url({
		       "certificate": "MIIEDTCCAvegAwIBAgIRAP8...",
		       "reason": 4
		     }),
		     "signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
		   }
	*/
	logger := acme.logger.WithField("method", "revokeCertificate")

	if certificate == nil {
		logger.Error("No certificate")
		return errors.New("No certificate")
	}

	if acme.accountURL == "" {
		logger.Error("No account URL saved. Create account before revoking certificate.")
		return errors.New("Missing account URL - can't set kid")
	}

	payload := map[string]interface{}{
		"certificate": certificate,
	}

	headers := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("kid"): acme.accountURL,
	}

	_, err := acme.doJosePostRequest(acme.endpoints.RevokeCert, headers, payload)
	if err != nil {
		logger.Error("Error revoking certificate: ", err)
		return err
	}

	return nil
}
