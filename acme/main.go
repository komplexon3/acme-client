package main

import (
	"os"

	flags "github.com/jessevdk/go-flags"

	gin "github.com/gin-gonic/gin"
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

var config struct {
	Dir    string   `long:"dir" description:"Directory URL of the ACME server that should be used." required:"true"`
	Record string   `long:"record" description:"IPv4 address which must be returned by your DNS server for all A-record queries." required:"true"`
	Domain []string `long:"domain" description:"Domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net." required:"true"`
	Revoke bool     `long:"revoke" description:"If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate."`
}

func main() {
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

	// setting up gin (test...)
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	r.Run() // listen and serve on
}
