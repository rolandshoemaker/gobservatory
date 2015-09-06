package core

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

type ServerConfig struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

// PoolFromPEM constructs a x509.CertPool containing all the certificates in the
// PEM file at path
func PoolFromPEM(filename string) (*x509.CertPool, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(content); !ok {
		return nil, fmt.Errorf("Couldn't parse certificates from PEM file")
	}
	return pool, nil
}

func Fingerprint(cert *x509.Certificate) []byte {
	hash := sha256.Sum256(cert.Raw)
	return hash[:]
}
