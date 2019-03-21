package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

func Certificate(certPEMBlock []byte) (*x509.Certificate, error) {
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatal("failed to read the CA certificate: unexpected content")
	}
	cer, err := x509.ParseCertificate(certDERBlock.Bytes)
	return cer, err
}

func LoadCertificate(filename string) (*x509.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Certificate(certPEMBlock)
}

func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return c, err
	}
	c.Leaf, err = x509.ParseCertificate(c.Certificate[0])
	return c, err
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func MakeCSR(name string) ([]byte, interface{}, error) {
	if !ValidName(name) {
		return nil, nil, errors.New("invalid name")
	}
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: name,
		},
		DNSNames: []string{name},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privkey)
	return csr, privkey, err
}

func SignCert(ca tls.Certificate, csr []byte, expiry time.Duration) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		Subject:  req.Subject,
		DNSNames: req.DNSNames,

		SerialNumber:          serial,
		NotAfter:              time.Now().Add(expiry),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, ca.Leaf, req.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), nil
}

func NewCA(commonName, certFilename, keyFilename string) {
	privkey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},

		NotAfter:              time.Now().AddDate(10, 0, 0),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, privkey.Public(), privkey)
	if err != nil {
		log.Fatal(err)
	}

	SavePrivateKey(keyFilename, privkey)
	SaveCertificate(certFilename, cert)
}

func SavePrivateKey(filename string, key interface{}) {
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(filename, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	if err != nil {
		log.Fatal(err)
	}
}

func SaveCertificate(filename string, cert []byte) {
	err := ioutil.WriteFile(filename, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func ValidName(name string) bool {
	if name == "" {
		return false
	}
	if name[0] == '-' {
		return false
	}
	for _, char := range name {
		switch {
		case char >= '0' && char <= '9':
			continue
		case char >= 'A' && char <= 'Z':
			continue
		case char >= 'a' && char <= 'z':
			continue
		case char == '.' || char == '-':
			continue
		default:
			return false
		}
	}
	return true
}

func ValidCSR(b []byte) bool {
	_, err := x509.ParseCertificateRequest(b)
	return err == nil
}
