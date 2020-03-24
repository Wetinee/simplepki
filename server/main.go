package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/crvv/simplepki/pki"
)

type store struct {
	sync.Mutex
	csr map[string][]byte
	cer map[string][]byte
}

func (s *store) AddCert(name string, cer []byte) bool {
	if _, err := pki.Certificate(cer); err != nil {
		log.Println("invalid certificate")
		return false
	}
	s.Lock()
	defer s.Unlock()
	if _, ok := s.cer[name]; ok {
		return false
	}
	delete(s.csr, name)
	s.cer[name] = cer
	return true
}

func (s *store) AddCSR(name string, csr []byte) bool {
	if !pki.ValidCSR(csr) {
		log.Println(base64.StdEncoding.EncodeToString(csr))
		log.Println("invalid csr")
		return false
	}
	s.Lock()
	defer s.Unlock()
	_, ok1 := s.csr[name]
	_, ok2 := s.cer[name]
	if ok1 || ok2 {
		log.Println("conflict")
		return false
	}
	s.csr[name] = csr
	return true
}

func (s *store) GetCert(name string) []byte {
	s.Lock()
	defer s.Unlock()
	b, ok := s.cer[name]
	if ok {
		return b
	}
	return nil
}

func (s *store) GetCSR(name string) []byte {
	s.Lock()
	defer s.Unlock()
	b, ok := s.csr[name]
	if ok {
		return b
	}
	return nil
}

func (s *store) ListCSR() []string {
	s.Lock()
	defer s.Unlock()
	names := make([]string, 0, len(s.csr))
	for name := range s.csr {
		names = append(names, name)
	}
	return names
}

func (s *store) ListCert() []string {
	s.Lock()
	defer s.Unlock()
	names := make([]string, 0, len(s.csr))
	for name := range s.cer {
		names = append(names, name)
	}
	return names
}

var db = &store{
	csr: map[string][]byte{},
	cer: map[string][]byte{},
}

func main() {
	http.HandleFunc("/csr/", func(w http.ResponseWriter, req *http.Request) {
		name := req.URL.Path[5:]
		if name == "" && req.Method == "GET" {
			err := json.NewEncoder(w).Encode(db.ListCSR())
			if err != nil {
				log.Println(err)
			}
			return
		}
		if !pki.ValidName(name) {
			http.Error(w, "name is not valid", http.StatusBadRequest)
			return
		}
		switch req.Method {
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		case "POST":
			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				log.Println(err)
				return
			}
			ok := db.AddCSR(name, b)
			if !ok {
				http.Error(w, "", http.StatusBadRequest)
				return
			}
		case "GET":
			b := db.GetCSR(name)
			if b == nil {
				http.Error(w, "", http.StatusBadRequest)
				return
			}
			_, err := w.Write(b)
			if err != nil {
				log.Println(err)
				return
			}
		}
	})
	http.HandleFunc("/cer/", func(w http.ResponseWriter, req *http.Request) {
		name := req.URL.Path[5:]
		if name == "" && req.Method == "GET" {
			err := json.NewEncoder(w).Encode(db.ListCert())
			if err != nil {
				log.Println(err)
			}
			return
		}
		if !pki.ValidName(name) {
			http.Error(w, "name is not valid", http.StatusBadRequest)
			return
		}
		switch req.Method {
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		case "POST":
			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				log.Println(err)
				return
			}
			ok := db.AddCert(name, b)
			if !ok {
				http.Error(w, "", http.StatusBadRequest)
				return
			}
		case "GET":
			b := db.GetCert(name)
			if b == nil {
				http.Error(w, "", http.StatusBadRequest)
				return
			}
			_, err := w.Write(b)
			if err != nil {
				log.Println(err)
				return
			}
		}
	})
	err := http.ListenAndServe(":44332", nil)
	log.Fatal(err)
}
