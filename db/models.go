package db

import "time"

type ASN struct {
	Number   int       `db:"number"`
	Name     string    `db:"name"`
	LastSeen time.Time `db:"last_seen"`
}

type RevokedCertificate struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	RevocationReason       int    `db:"revocation_reason"`
	ByOCSP                 bool   `db:"by_ocsp"`
	ByCRL                  bool   `db:"by_crl"`
}

// CertificateChain describes a certificate chain and it's validity properties
type CertificateChain struct {
	Certs         int
	Fingerprint   []byte
	NssValidity   bool
	MsValidity    bool
	TransValidity bool
	Validity      bool
}
