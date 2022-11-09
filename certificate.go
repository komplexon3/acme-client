package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
)

type certificate struct {
	certificateURL string
	certificate    string
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

	headers := map[string]interface{}{
		"kid": acme.accountURL,
		"url": certificateURL,
	}

	req, err := acme.josePostRequest(certificateURL, headers, nil)
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
	acme.currentNonce = resp.Header.Get("Replay-Nonce")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error reading response body: ", err)
		return nil, err
	}

	return &certificate{
		certificateURL: certificateURL,
		certificate:    string(body),
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

	// extract cert from pem
	var rawCert []byte
	var block *pem.Block
	var rest []byte = []byte(certificate.certificate)
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			return errors.New("No certificate found in PEM")
		}
		if block.Type == "CERTIFICATE" {
			rawCert = block.Bytes
			break
		}
	}

	payload := map[string]interface{}{
		"certificate": base64.RawURLEncoding.EncodeToString(rawCert),
	}

	headers := map[string]interface{}{
		"kid": acme.accountURL,
	}

	_, err := acme.doJosePostRequest(acme.endpoints.RevokeCert, headers, payload)
	if err != nil {
		logger.Error("Error revoking certificate: ", err)
		return err
	}

	return nil
}
