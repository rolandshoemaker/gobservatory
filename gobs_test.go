package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

const certsJSON = `["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"]`

func BenchmarkAddCertificatesSerial(b *testing.B) {
	var certDERs []string
	err := json.Unmarshal([]byte(certsJSON), &certDERs)
	if err != nil {
		fmt.Println(err)
		return
	}
	var certs []*x509.Certificate
	for _, b := range certDERs {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			fmt.Println(err)
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Println(err)
			return
		}
		certs = append(certs, cert)
	}

	b.ResetTimer()
	obs := newObservatory("localhost", "80", "v4.whois.cymru.com", "43")

	for i := 0; i < b.N; i++ {
		obs.addCertificates(certs)
	}
}

func BenchmarkAddCertificatesParallel(b *testing.B) {
	var certDERs []string
	err := json.Unmarshal([]byte(certsJSON), &certDERs)
	if err != nil {
		fmt.Println(err)
		return
	}
	var certs []*x509.Certificate
	for _, b := range certDERs {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			fmt.Println(err)
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Println(err)
			return
		}
		certs = append(certs, cert)
	}

	b.ResetTimer()
	obs := newObservatory("localhost", "80", "v4.whois.cymru.com", "43")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			obs.addCertificates(certs)
		}
	})
}

func TestAddCertificates(t *testing.T) {
	var certDERs []string
	err := json.Unmarshal([]byte(certsJSON), &certDERs)
	if err != nil {
		fmt.Println(err)
		return
	}
	var certs []*x509.Certificate
	for _, b := range certDERs {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			fmt.Println(err)
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Println(err)
			return
		}
		certs = append(certs, cert)
	}

	obs := newObservatory("localhost", "80", "v4.whois.cymru.com", "43")
	err = obs.addCertificates(certs)
	test.AssertNotError(t, err, "Couldn't add certificates in chain")
}
