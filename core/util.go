package core

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
)

// RevocationReasons maps reason codes to the text descriptions
var RevocationReasons = map[int]string{
	0: "unspecified",
	1: "keyCompromise",
	2: "cACompromise",
	3: "affiliationChanged",
	4: "superseded",
	5: "cessationOfOperation",
	6: "certificateHold",
	// 7 is unused
	8:  "removeFromCRL",
	9:  "privilegeWithdrawn",
	10: "aAcompromise",
}

// CertificateChain describes a certificate chain and it's validity properties
type CertificateChain struct {
	Certs         []*x509.Certificate
	Fingerprint   []byte
	NssValidity   bool
	MsValidity    bool
	TransValidity bool
	Validity      bool
}

// ServerConfig provides a simple reusable config most servers need
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

// StringToFingerprint converts a string fingerprint to a byte fingerprint
func StringToFingerprint(fpStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(fpStr)

}

// Fingerprint creates a SHA256 certificate fingerprint
func Fingerprint(cert *x509.Certificate) []byte {
	hash := sha256.Sum256(cert.Raw)
	return hash[:]
}

// SerialToString converts a x509 style serial number to a hex string
func SerialToString(serial *big.Int) string {
	return fmt.Sprintf("%032X", serial)
}
