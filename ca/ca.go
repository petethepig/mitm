package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"time"
)

type CertificateAuthority struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	cache  sync.Map
}

func New(c *x509.Certificate, p *rsa.PrivateKey) *CertificateAuthority {
	return &CertificateAuthority{caCert: c, caKey: p}
}

func GeneratePair() (*x509.Certificate, *rsa.PrivateKey, error) {
	now := time.Now()
	validFor := 3 * 365 * 24 * time.Hour
	rsaBits := 2048
	notBefore := now.Truncate(validFor)
	notAfter := now.Add(validFor)

	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	sbj := pkix.Name{
		CommonName: "mitm CA",
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               sbj,
		Issuer:                sbj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}
func (ca *CertificateAuthority) IssueCert(hostname string) (*tls.Certificate, error) {
	certI, ok := ca.cache.Load(hostname)
	if ok {
		return certI.(*tls.Certificate), nil
	}

	now := time.Now()
	validFor := 365 * 24 * time.Hour
	rsaBits := 2048
	notBefore := now.Truncate(validFor)
	notAfter := now.Add(validFor)

	parentCert := ca.caCert
	parentKey := ca.caKey

	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		Issuer:                parentCert.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}
	ca.cache.Store(hostname, &cert)
	return &cert, nil
}
