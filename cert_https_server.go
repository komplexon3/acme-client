package main

import (
	gin "github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	ginlogrus "github.com/toorop/gin-logrus"
)

type CertHttpsServer struct {
	server          *gin.Engine
	keyFile         string
	certificateFile string
	port            string
	logger          *logrus.Entry
}

func InitCertServer(logger *logrus.Entry, port string, keyFile string, certificateFile string) *CertHttpsServer {

	server := gin.New()
	server.Use(ginlogrus.Logger(logger), gin.Recovery())
	server.GET("/", func(c *gin.Context) {
		c.String(200, "Serving HTTPS content")
	})

	certHttpsServer := CertHttpsServer{
		server:          server,
		keyFile:         keyFile,
		certificateFile: certificateFile,
		port:            port,
		logger:          logger,
	}

	return &certHttpsServer

}

func (c *CertHttpsServer) Start() {
	// start the server
	c.server.RunTLS(":"+c.port, c.certificateFile, c.keyFile)
}
