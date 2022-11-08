package acme_http

import (
	"strings"

	store "github.com/komplexon3/acme-client/store"
	ginlogrus "github.com/toorop/gin-logrus"

	gin "github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type HTTPServer struct {
	server *gin.Engine
	port   string
	store  *store.Store
	logger *logrus.Entry
}

func initHTTPServer(logger *logrus.Entry) *HTTPServer {
	server := gin.New()
	server.Use(ginlogrus.Logger(logger), gin.Recovery())

	httpStore := store.RunStore()

	httpServer := HTTPServer{
		server: server,
		port:   ":5002",
		store:  httpStore,
		logger: logger,
	}

	return &httpServer
}

func (httpServer *HTTPServer) handleRequest(c *gin.Context) {
	challengePath := strings.TrimPrefix(c.Request.URL.Path, "/.well-known/acme-challenge/")
	res := httpServer.store.Get(challengePath)
	c.String(200, res)
}

func (httpServer *HTTPServer) Start() {
	httpServer.server.GET("/*", httpServer.handleRequest)
	httpServer.server.Run(httpServer.port)
}

func (httpServer *HTTPServer) AddChallengePath(challengePath string, value string) error {
	return httpServer.store.Set(challengePath, value)
}

func (httpServer *HTTPServer) DelChallengePath(challengePath string) error {
	return httpServer.store.Del(challengePath)
}
