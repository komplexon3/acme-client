package main

/* TODO: IMPORTANT
* remove jose library and write your own! Only use it to get everyting working
* then use your own!
 */

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/komplexon3/acme-client/acme_http"
	"github.com/komplexon3/acme-client/dns"

	gin "github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	ginlogrus "github.com/toorop/gin-logrus"
)

/*
*
*	Positional arguments:
*	Challenge type
*	(required, {dns01 | http01}) indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dns-01 and http-01 challenges, respectively.

*	Keyword arguments:
*	--dir DIR_URL
*	(required) DIR_URL is the directory URL of the ACME server that should be used.
*	--record IPv4_ADDRESS
*	(required) IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.
*	--domain DOMAIN
*	(required, multiple) DOMAIN  is the domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.
*	--revoke
*	(optional) If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.
 */

type ChallengeType string

const (
	DNS01  ChallengeType = "dns01"
	HTTP01 ChallengeType = "http01"
)

type acmeEndpoints struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type acmeClient struct {
	dir                   string
	endpoints             acmeEndpoints
	currentNonce          string
	logger                *logrus.Entry
	accountURL            string
	privateKey            *ecdsa.PrivateKey
	dnsProvider           *dns.DNSServer
	httpChallengeProvider *acme_http.HTTPServer
	httpClient            *http.Client
}

type config struct {
	Dir    string   `long:"dir" description:"Directory URL of the ACME server that should be used." required:"true"`
	Record string   `long:"record" description:"IPv4 address which must be returned by your DNS server for all A-record queries." required:"true"`
	Domain []string `long:"domain" description:"Domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net." required:"true"`
	Revoke bool     `long:"revoke" description:"If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate."`
	Proxy  string   `long:"proxy" description:"If present, all outdoing requests will be routed though the procy and TLS will no longer be verified properly."`
}

func setup(logger *logrus.Entry, mode ChallengeType, conf config) *acmeClient {
	acmeClient := acmeClient{
		logger:       logger,
		currentNonce: "",
		accountURL:   "",
	}

	client, err := setupClient("pebble.minica.pem", conf.Proxy)
	if err != nil {
		logger.Fatalf("Error setting up client: %v", err)
	}

	acmeClient.httpClient = client

	if conf.Proxy != "" {
		print("===================================\n")
		print("= WARNING WARNING WARNING WARNING =\n")
		print("All traffic is routed through " + conf.Proxy + "and TLS is not verified!\n")
		print("\n=================================\n")
	}

	// get directory
	endpoints, err := getDirectory(*client, conf.Dir)
	if err != nil {
		logger.Fatalf("Error getting directory: %v", err)
	}
	acmeClient.endpoints = *endpoints

	acmeClient.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Fatalf("Error generating key: %v", err)
	}

	dnsServerLogger := logger.WithField("server", "dns-challenge")
	acmeClient.dnsProvider = dns.InitDNSProvider(dnsServerLogger, net.ParseIP(conf.Record))

	httpServerLogger := logger.WithField("server", "http-challenge")
	acmeClient.httpChallengeProvider = acme_http.InitHTTPProvider(httpServerLogger)

	return &acmeClient

}

func main() {

	loggerBase := logrus.New()
	loggerBase.Level = logrus.DebugLevel

	if len(os.Args) == 1 {
		println("Usage: acme {dns01 | http01} [options]")
		os.Exit(1)
	}

	var mode ChallengeType = ChallengeType(os.Args[1])
	var conf config
	var parser = flags.NewParser(&conf, flags.Default)

	if mode != DNS01 && mode != HTTP01 {
		loggerBase.Fatal("Challenge type must be dns01 or http01")
	}

	if _, err := parser.Parse(); err != nil {
		loggerBase.Fatal(err)
	}

	log := loggerBase.WithFields(logrus.Fields{
		"mode":   mode,
		"dir":    conf.Dir,
		"Record": conf.Record,
		"Domain": strings.Join(conf.Domain, " "),
		"Revoke": conf.Revoke,
	})

	// setup client
	acmeClient := setup(log, mode, conf)

	// start dns provider
	go acmeClient.dnsProvider.Start()

	// start http provider
	go acmeClient.httpChallengeProvider.Start()

	// create account
	if err := acmeClient.createAccount(); err != nil {
		log.Fatalf("Error creating account: %v", err)
	}
	log.WithField("account", acmeClient.accountURL).Info("Account created")

	// create order

	order, err := acmeClient.createOrder(conf.Domain)
	if err != nil {
		log.Fatalf("Error creating order: %v", err)
	}
	log.WithField("order", order).Info("Order created")

	// get authorizations
	var authorizations []authorization
	for _, authorization := range order.authorizations {
		auth, _, err := acmeClient.getAuthorization(authorization.authorizationURL)
		if err != nil {
			log.Fatalf("Error getting authorization: %v", err)
		}
		authorizations = append(authorizations, *auth)
	}
	order.authorizations = authorizations

	log.WithField("authorizations", authorizations).Info("Authorizations retrieved")

	// register challenges, respond to them, poll their authorization, and deregister them
	for _, auth := range authorizations {
		challenge, tripwire, err := acmeClient.registerChallenge(&auth, mode)
		if err != nil {
			log.Fatalf("Error registering challenge: %v", err)
		}
		log.WithField("challenge", challenge).Info("Challenge registered")
		if err := acmeClient.respondToChallenge(challenge); err != nil {
			log.Fatalf("Error responding to challenge: %v", err)
		}

		// wait until the challenge is verified before continuing
		<-tripwire
		//_ = tripwire

		log.WithField("challenge", challenge).Info("Responded to challenge")
		if err := acmeClient.pollAuthorization(&auth, 10); err != nil {
			log.Fatalf("Error polling authorization: %v", err)
		}
		log.WithField("authorization", auth).Info("Authorization complete")
		if err := acmeClient.deregisterChallenge(challenge); err != nil {
			log.Fatalf("Error deregistering challenge: %v", err)
		}
		log.WithField("challenge", challenge).Info("Challenge deregistered")
	}

	// generate key for certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	// finalize order
	if err = acmeClient.finalizeOrder(order, key); err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	// poll status
	if err := acmeClient.pollUntilReady(order, 10); err != nil {
		log.Fatalf("Error polling status: %v", err)
	}

	// download certificate
	cert, err := acmeClient.getCertificate(order.certificateURL)
	if err != nil {
		log.Fatalf("Error downloading certificate: %v", err)
	}

	// write certificate and key
	certFile, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Error creating cert.pem: %v", err)
	}
	if _, err := certFile.Write([]byte(cert.certificate)); err != nil {
		log.Fatalf("Error writing certificate: %v", err)
	} else {
		certFile.Close()
	}

	rawKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("Error marshalling private key: %v", err)
	}
	block := &pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: rawKey,
	}
	keyFile, err := os.Create("key.pem")
	if err != nil {
		log.Fatalf("Error creating key.pem: %v", err)
	}
	if err = pem.Encode(keyFile, block); err != nil {
		log.Fatalf("Error writing private key: %v", err)
	} else {
		keyFile.Close()
	}

	// setup server with certificate
	certHttpsLogger := loggerBase.WithFields(logrus.Fields{
		"server": "cert-https",
		"cert":   "cert.pem",
		"key":    "key.pem",
	})
	certHttpsServer := InitCertServer(certHttpsLogger, "5001", "key.pem", "cert.pem")
	go certHttpsServer.Start()

	// revoke certificate if requested
	if conf.Revoke {
		if err := acmeClient.revokeCertificate(cert); err != nil {
			log.Fatalf("Error revoking certificate: %v", err)
		}
	}

	// create and start shutdown server
	// when called, it will simply call os.Exit(0) after a 1s delay
	shutdownChannel := make(chan int, 1)
	shutdownServerLogger := log.WithField("server", "shutdownServer")
	shutdownServer := gin.New()
	shutdownServer.Use(ginlogrus.Logger(shutdownServerLogger), gin.Recovery())
	shutdownServer.GET("/shutdown", func(c *gin.Context) {
		shutdownServerLogger.Info("Shutdown server called")
		c.String(200, "Shutting down...")
		shutdownChannel <- 0
	})
	go shutdownServer.Run(":5003")

	code := <-shutdownChannel
	close(shutdownChannel)
	log.Info("Shutting down...")
	acmeClient.dnsProvider.Stop()
	time.Sleep(time.Second)
	os.Exit(code)
}
