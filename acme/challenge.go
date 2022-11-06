package main

type challenge struct {
	challengeType string `json:"type"`
	url           string `json:"url"`
	token         string `json:"token"`
}

type dnsRegistration struct {
}

func (acme *acmeConfig) registerDNSChallenge(chal *challenge) (*dnsRegistration, error) {
	// TODO
	return nil, nil
}

func (acme *acmeConfig) deregisterDNSChallenge(reg *dnsRegistration) error {
	// TODO
	return nil
}

func (acme *acmeConfig) registerHTTPChallenge(chal *challenge) error {
	// TODO
	return nil
}
