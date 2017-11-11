package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/petethepig/mitm/ca"
)

func readCertAndKey(caCertPath, caKeyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBytes, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func main() {
	log.SetFlags(0)

	var (
		bindAddr   string
		caCertPath string
		caKeyPath  string
	)

	flag.StringVar(&bindAddr, "bind-addr", ":443", "bind address")
	flag.StringVar(&caCertPath, "ca-cert", "", "path to CA certificate path")
	flag.StringVar(&caKeyPath, "ca-key", "", "path to CA key path")
	flag.Parse()

	if caCertPath == "" || caKeyPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	cert, key, err := readCertAndKey(caCertPath, caKeyPath)
	if err != nil {
		panic(err)
	}
	ca := ca.New(cert, key)

	config := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.IssueCert(chi.ServerName)
		},
	}

	l, err := tls.Listen("tcp", bindAddr, config)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}

		go handleConn(conn.(*tls.Conn))
	}
}

func handleConn(conn *tls.Conn) {
	defer conn.Close()

	err := conn.Handshake()
	if err != nil {
		log.Println("handshake failed", err)
		return
	}

	hostname := conn.ConnectionState().ServerName
	localAddr := conn.LocalAddr().String()
	_, port, err := net.SplitHostPort(localAddr)

	if err != nil {
		log.Println("failed to split host and port", localAddr)
		return
	}

	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	upstreamAddr := hostname + ":" + port
	upstream, err := tls.Dial("tcp", upstreamAddr, clientConfig)

	if err != nil {
		log.Println("failed to establish upstream connection", err)
		return
	}

	log.Printf("connected %s and %s", conn.RemoteAddr().String(), hostname)
	duplex(conn, upstream)
}
