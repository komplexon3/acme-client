package jose

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
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

func GetJWK(key ecdsa.PublicKey) *JWK {
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}
	return jwk
}

func (jwk *JWK) Thumbprint() []byte {
	thumbprint := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	h := sha256.New()
	h.Write([]byte(thumbprint))
	return h.Sum(nil)
}

func (jwt *JWT) SignJWT(key *ecdsa.PrivateKey, nonce string) (string, error) {
	header, err := SerializeSegment(jwt.Header)
	if err != nil {
		return "", err
	}
	payload, err := SerializeSegment(jwt.Payload)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(header + "." + payload))

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

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

	signature, err := jwt.SignJWT(&key, nonce)
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
