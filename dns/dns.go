package dns

import (
	"net"

	store "github.com/komplexon3/acme-client/store"
	miekg_dns "github.com/miekg/dns"

	"github.com/sirupsen/logrus"
)

type DNSServer struct {
	server   *miekg_dns.Server
	store    *store.Store
	logger   *logrus.Entry
	aReponse net.IP
}

type DNSHandler struct {
	store    *store.Store
	logger   *logrus.Entry
	aReponse net.IP
}

func InitDNSProvider(logger *logrus.Entry, aResponse net.IP) *DNSServer {
	dnsStore := store.RunStore(logger.WithField("module", "store"))

	dnsHandler := DNSHandler{
		store:    dnsStore,
		logger:   logger,
		aReponse: aResponse,
	}

	dnsServer := &DNSServer{
		server: &miekg_dns.Server{
			Addr:    ":10053",
			Net:     "udp",
			Handler: &dnsHandler,
		},
		store:    dnsStore,
		logger:   logger,
		aReponse: aResponse,
	}

	return dnsServer
}

func (dnsServer *DNSServer) AddTXTRecord(domain string, value string) error {
	return dnsServer.store.Set(domain, value)
}

func (dnsServer *DNSServer) DelTXTRecord(domain string) error {
	return dnsServer.store.Del(domain)
}

func (dnsServer *DNSServer) Start() error {
	return dnsServer.server.ListenAndServe()
}

func (dnsServer *DNSServer) Stop() error {
	return dnsServer.server.Shutdown()
}

func (dnsHandler *DNSHandler) ServeDNS(w miekg_dns.ResponseWriter, r *miekg_dns.Msg) {
	msg := miekg_dns.Msg{}
	msg.SetReply(r)
	dnsHandler.logger.WithField("request", r).Info("DNS request")
	switch r.Question[0].Qtype {
	case miekg_dns.TypeTXT:
		domain := msg.Question[0].Name
		res := dnsHandler.store.Get(domain)
		if res != "" {
			msg.Answer = append(msg.Answer, &miekg_dns.TXT{
				Hdr: miekg_dns.RR_Header{Name: domain, Rrtype: miekg_dns.TypeTXT, Class: miekg_dns.ClassANY, Ttl: 300},
				Txt: []string{res},
			})
		}
	case miekg_dns.TypeA:
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &miekg_dns.A{
			Hdr: miekg_dns.RR_Header{Name: domain, Rrtype: miekg_dns.TypeA, Class: miekg_dns.ClassANY, Ttl: 300},
			A:   dnsHandler.aReponse,
		})
	}
	w.WriteMsg(&msg)
}
