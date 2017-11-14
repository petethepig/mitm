package dns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

type Server struct {
	upstreamAddr string
	overrides    map[string]net.IP

	udpServer *dns.Server
	tcpServer *dns.Server
}

func (d *Server) Close() {
	d.udpServer.Shutdown()
	d.tcpServer.Shutdown()
}

func StartServer(bindAddr, upstreamAddr string, overrides map[string]string) *Server {
	d := &Server{
		upstreamAddr: upstreamAddr,
		overrides:    make(map[string]net.IP),
	}

	for hostname, ipAddr := range overrides {
		d.overrides[dns.Fqdn(hostname)] = net.ParseIP(ipAddr)
	}

	d.udpServer = &dns.Server{Addr: bindAddr, Net: "udp", Handler: dns.HandlerFunc(d.handleRequest)}
	d.tcpServer = &dns.Server{Addr: bindAddr, Net: "tcp", Handler: dns.HandlerFunc(d.handleRequest)}

	go func() {
		d.udpServer.ListenAndServe()
	}()
	go func() {
		d.tcpServer.ListenAndServe()
	}()

	return d
}

func (d *Server) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	questionHostname := req.Question[0].Name

	for hostname, ipAddr := range d.overrides {
		if strings.HasSuffix(questionHostname, hostname) {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   questionHostname,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3600,
					},
					A: ipAddr,
				},
			}
			w.WriteMsg(m)
			return
		}
	}

	c := &dns.Client{Net: "udp"}
	resp, _, err := c.Exchange(req, d.upstreamAddr)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}
