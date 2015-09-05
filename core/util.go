package core

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

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
