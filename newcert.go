package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/crvv/simplepki/pki"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	log.SetFlags(log.LstdFlags|log.Lshortfile)
	ca, err := pki.LoadX509KeyPair("ca.cert", "ca.key")
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range os.Args[1:] {
		newCert(ca, name)
	}
}

func newCert(ca tls.Certificate, name string) {
	csr, privkey, err := pki.MakeCSR(name)
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := pki.SignCert(ca, csr, 360*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(name+".cert", certificate, 0644)
	if err != nil {
		log.Fatal(err)
	}
	pki.SavePrivateKey(name+".key", privkey)

	cert, err := pki.Certificate(certificate)
	if err != nil {
		log.Fatal(err)
	}
	pfxData, err := pkcs12.Encode(rand.Reader, privkey, cert, []*x509.Certificate{ca.Leaf}, "")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(name+".pfx", pfxData, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
