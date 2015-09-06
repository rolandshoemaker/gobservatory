package db

import "time"

type ASN struct {
	Number   int       `db:"number"`
	Name     string    `db:"name"`
	LastSeen time.Time `db:"last_seen"`
}

type RevokedCertificate struct {
	CertificateFingerprint []byte    `db:"certificate_fingerprint"`
	RevocationReason       int       `db:"revocation_reason"`
	FirstSeen              time.Time `db:"first_seen"`
	ByOCSP                 bool      `db:"by_ocsp"`
	ByCRL                  bool      `db:"by_crl"`
}
