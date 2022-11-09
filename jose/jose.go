package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type JWT struct {
	Header  map[string]interface{}
	Payload interface{}
}

type JWTDTO struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func SerializeSegment(data interface{}) (string, error) {
	if data == nil {
		return "", nil
	}

	json, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(json), "="), nil
}

func GetJWK(key ecdsa.PrivateKey) map[string]interface{} {
	publicKey := key.PublicKey
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
	}
	return jwk
}

func (jwt *JWT) SignJWT(key crypto.Signer, nonce string) (string, error) {
	header, err := SerializeSegment(jwt.Header)
	if err != nil {
		return "", err
	}
	payload, err := SerializeSegment(jwt.Payload)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(signature)
	_ = enc
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func (jwt *JWT) CreateSignedPayload(key ecdsa.PrivateKey, nonce string) ([]byte, error) {
	jwt.Header["alg"] = "ES256"
	jwt.Header["nonce"] = nonce

	header, err := SerializeSegment(jwt.Header)
	if err != nil {
		return nil, err
	}
	payload, err := SerializeSegment(jwt.Payload)
	if err != nil {
		return nil, err
	}

	signingKey := crypto.Signer(&key)
	signature, err := jwt.SignJWT(signingKey, nonce)
	if err != nil {
		return nil, err
	}

	msg := JWTDTO{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}

	return json.Marshal(msg)
}
