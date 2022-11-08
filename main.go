package main

/* TODO: IMPORTANT
* remove jose library and write your own! Only use it to get everyting working
* then use your own!
 */

import (
	"crypto/ecdsa"
	"net"
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
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type acmeConfig struct {
	dir                   string
	endpoints             acmeEndpoints
	currentNonce          string
	logger                *logrus.Logger
	accountURL            string
	orders                []order
	privateKey            *ecdsa.PrivateKey
	dnsProvider           dns.DNSServer
	httpChallengeProvider acme_http.HTTPServer
}

var config struct {
	Dir    string   `long:"dir" description:"Directory URL of the ACME server that should be used." required:"true"`
	Record string   `long:"record" description:"IPv4 address which must be returned by your DNS server for all A-record queries." required:"true"`
	Domain []string `long:"domain" description:"Domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net." required:"true"`
	Revoke bool     `long:"revoke" description:"If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate."`
}

func main() {

	loggerBase := logrus.New()

	if len(os.Args) == 1 {
		println("Usage: acme {dns01 | http01} [options]")
		os.Exit(1)
	}

	var mode ChallengeType = ChallengeType(os.Args[1])
	var parser = flags.NewParser(&config, flags.Default)

	if mode != DNS01 && mode != HTTP01 {
		println("Challenge type must be dns01 or http01")
		os.Exit(1)
	}

	if _, err := parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}

	log := loggerBase.WithFields(logrus.Fields{
		"mode":   mode,
		"dir":    config.Dir,
		"Record": config.Record,
		"Domain": strings.Join(config.Domain, " "),
		"Revoke": config.Revoke,
	})

	// setting up gin (test...)
	httpSererLogger := log.WithField("server", "http")
	httpServer := gin.New()
	httpServer.Use(ginlogrus.Logger(httpSererLogger), gin.Recovery())
	httpServer.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	go httpServer.Run() // listen and serve on

	// dns
	dnsServerLogger := log.WithField("server", "dns")
	dnsServer := dns.InitDNSServer(dnsServerLogger, net.ParseIP(config.Record))
	go dnsServer.Start()

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
	dnsServer.Stop()
	time.Sleep(1 * time.Second)
	os.Exit(code)
}
