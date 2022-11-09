package main

/* TODO: IMPORTANT
* remove jose library and write your own! Only use it to get everyting working
* then use your own!
 */

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	orders                []Order
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
}

func setup(logger *logrus.Entry, mode ChallengeType, conf config) *acmeClient {
	acmeClient := acmeClient{
		logger:       logger,
		currentNonce: "",
		accountURL:   "",
		orders:       []Order{},
	}

	client, err := setupClient("project/pebble.minica.pem", "http://k3-MBA.local:9090")
	if err != nil {
		logger.Fatalf("Error setting up client: %v", err)
	}

	acmeClient.httpClient = client

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
		auth, err := acmeClient.getAuthorization(authorization.authorizationURL)
		if err != nil {
			log.Fatalf("Error getting authorization: %v", err)
		}
		authorizations = append(authorizations, *auth)
	}
	order.authorizations = authorizations

	log.WithField("authorizations", authorizations).Info("Authorizations retrieved")

	// select challenges of mathing mode
	challengeType := func() string {
		switch mode {
		case DNS01:
			return "dns-01"
		case HTTP01:
			return "http-01"
		default:
			loggerBase.Fatal("Challenge type must be dns01 or http01")
			return ""
		}
	}()
	var challenges []challenge
	for _, auth := range authorizations {
		for _, challenge := range auth.challenges {
			if challenge.Type == challengeType {
				challenges = append(challenges, challenge)
			}
		}
	}

	if len(challenges) == 0 {
		log.Fatal("No challenges mathing the mode found")
	}

	log.WithField("challenges", len(challenges)).Info("Challenges selected")

	for _, challenge := range challenges {
		log.Info(challenge)
	}

	switch mode {
	case DNS01:
		// setup dns challenges
		for _, challenge := range challenges {
			if err := acmeClient.registerDNSChallenge(conf.Domain[0], &challenge); err != nil {
				log.Fatalf("Error registering DNS challenge: %v", err)
			}
			if err := acmeClient.respondToChallenge(&challenge); err != nil {
				log.Fatalf("Error responding to challenge: %v", err)
			}
		}
	case HTTP01:
		// setup http challenges
		for _, challenge := range challenges {
			if err := acmeClient.registerHTTPChallenge(&challenge); err != nil {
				log.Fatalf("Error registering HTTP challenge: %v", err)
			}
			if err := acmeClient.respondToChallenge(&challenge); err != nil {
				log.Fatalf("Error responding to challenge: %v", err)
			}
		}
	}

	// check authorizations
	// sketchy for now - check dns and http server for trigger later
	valid := false
	for !valid {
		for _, auth := range authorizations {
			authorizations, err := acmeClient.getAuthorization(auth.authorizationURL)
			if err != nil {
				log.Fatalf("Error getting authorization: %v", err)
			}
			if authorizations.status == "valid" {
				valid = true
			}
		}
		time.Sleep(1 * time.Second)
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
	time.Sleep(1 * time.Second)
	os.Exit(code)
}
