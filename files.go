package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

func isPem(in []byte) bool {
	return bytes.HasPrefix(in, []byte("-----"))
}

func pemToDer(in []byte) []byte {
	b, _ := pem.Decode(in)
	return b.Bytes
}

func readDerOrPem(filePath string) ([]byte, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if isPem(b) {
		b = pemToDer(b)
	}
	return b, nil
}

func readCert(caCertPath string) (*x509.Certificate, error) {
	certBytes, err := readDerOrPem(caCertPath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func readKey(caKeyPath string) (*rsa.PrivateKey, error) {
	keyBytes, err := readDerOrPem(caKeyPath)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func writePem(path string, data []byte) error {
	return ioutil.WriteFile(path, data, 0644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
