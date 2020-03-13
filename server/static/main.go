package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"syscall/js"
	"time"

	"github.com/crvv/simplepki/pki"
	"software.sslmate.com/src/go-pkcs12"
)

func makeCSR(this js.Value, args []js.Value) interface{} {
	name := args[0].String()
	csr, key, err := pki.MakeCSR(name)
	if err != nil {
		log.Println(err)
		return nil
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return map[string]interface{}{
		"name": name,
		"key":  base64.StdEncoding.EncodeToString(keyPEM),
		"csr":  base64.StdEncoding.EncodeToString(csr),
	}
}

func sign(this js.Value, args []js.Value) interface{} {
	cacert, err1 := base64.StdEncoding.DecodeString(args[0].String())
	cakey, err2 := base64.StdEncoding.DecodeString(args[1].String())
	csr, err3 := base64.StdEncoding.DecodeString(args[2].String())
	if err1 != nil || err2 != nil || err3 != nil {
		log.Println(err1, err2, err3)
		return nil
	}
	ca, err := pki.X509KeyPair(cacert, cakey)
	if err != nil {
		log.Println(err)
		return nil
	}
	cer, err := pki.SignCert(ca, csr, 360*24*time.Hour)
	if err != nil {
		log.Println(err)
		return nil
	}
	return base64.StdEncoding.EncodeToString(cer)
}

func getCAInfo(this js.Value, args []js.Value) interface{} {
	file1, err1 := base64.StdEncoding.DecodeString(args[0].String())
	file2, err2 := base64.StdEncoding.DecodeString(args[1].String())
	if err1 != nil || err2 != nil {
		log.Println(err1, err2)
	}
	ca1, err1 := pki.X509KeyPair(file1, file2)
	ca2, err2 := pki.X509KeyPair(file2, file1)
	var cer, key []byte
	var ca tls.Certificate
	switch {
	case err1 == nil:
		cer, key = file1, file2
		ca = ca1
	case err2 == nil:
		cer, key = file2, file1
		ca = ca2
	default:
		log.Println(err1, err2)
		return nil
	}
	return map[string]interface{}{
		"name": ca.Leaf.Subject.CommonName,
		"cert": base64.StdEncoding.EncodeToString(cer),
		"key":  base64.StdEncoding.EncodeToString(key),
	}
}

func marshalPFX(this js.Value, args []js.Value) interface{} {
	cert, err1 := base64.StdEncoding.DecodeString(args[0].String())
	key, err2 := base64.StdEncoding.DecodeString(args[1].String())
	ca, err3 := base64.StdEncoding.DecodeString(args[2].String())
	if err1 != nil || err2 != nil || err3 != nil {
		log.Println(err1, err2)
		return nil
	}

	cer, err := pki.X509KeyPair(cert, key)
	if err != nil {
		log.Println(err)
		return nil
	}
	cacert, err := pki.Certificate(ca)
	if err != nil {
		log.Println(err)
		return nil
	}
	pfxData, err := pkcs12.Encode(rand.Reader, cer.PrivateKey, cer.Leaf, []*x509.Certificate{cacert}, "")
	if err != nil {
		log.Println(err)
		return nil
	}
	return base64.StdEncoding.EncodeToString(pfxData)
}

func main() {
	js.Global().Set("makeCSR", js.FuncOf(makeCSR))
	js.Global().Set("sign", js.FuncOf(sign))
	js.Global().Set("getCAInfo", js.FuncOf(getCAInfo))
	js.Global().Set("marshalPFX", js.FuncOf(marshalPFX))
	select {}
}
