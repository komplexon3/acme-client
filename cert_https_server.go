package main

import (
	gin "github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	ginlogrus "github.com/toorop/gin-logrus"
)

type CertHttpsServer struct {
	server      *gin.Engine
	key         string // TODO: type probably needs to be changed
	certificate string // TODO: type probably needs to be changed
	port        string
	logger      *logrus.Logger
}

func Init(logger *logrus.Logger, port string, key string, certificate string) *CertHttpsServer {

	server := gin.New()
	server.Use(ginlogrus.Logger(logger), gin.Recovery())
	server.GET("/", func(c *gin.Context) {
		c.String(200, "Serving HTTPS content")
	})

	certHttpsServer := CertHttpsServer{
		server:      server,
		key:         key,
		certificate: certificate,
		port:        port,
		logger:      logger,
	}

	return &certHttpsServer

}

func (c *CertHttpsServer) Start() {
	// start the server
	c.server.RunTLS(":"+c.port, c.certificate, c.certificate)
}
