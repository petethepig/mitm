package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"

	"github.com/petethepig/mitm/ca"
)

func main() {
	log.SetFlags(0)

	var (
		bindAddr       string
		caCertPath     string
		caKeyPath      string
		generateCaPair bool
	)

	flag.StringVar(&bindAddr, "bind-addr", ":443", "bind address")
	flag.StringVar(&caCertPath, "ca-cert", "ca-cert.pem", "path to CA certificate path")
	flag.StringVar(&caKeyPath, "ca-key", "ca-key.pem", "path to CA key path")
	flag.BoolVar(&generateCaPair, "init", false, "call with this flag to generate CA key and cert")
	flag.Parse()

	if !fileExists(caCertPath) || !fileExists(caKeyPath) {
		flag.Usage()
		os.Exit(2)
	}

	if generateCaPair {
		cert, key, err := ca.GeneratePair()
		if err != nil {
			panic(err)
		}

		certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

		err = writePem(caCertPath, certPem)
		if err != nil {
			panic(err)
		}

		err = writePem(caKeyPath, keyPem)
		if err != nil {
			panic(err)
		}
		return
	}

	cert, err := readCert(caCertPath)
	if err != nil {
		panic(err)
	}

	key, err := readKey(caKeyPath)
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
