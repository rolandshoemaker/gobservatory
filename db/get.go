package database

import (
	"database/sql"

	"github.com/letsencrypt/boulder/core"
)

// IsRevoked checks the revoked_certificates table to quickly check if a certificate
// has been revoked
func (db *Database) IsRevoked(fingerprint []byte) (bool, string, error) {
	var reovcationReason int
	err := db.m.SelectOne(
		&reovcationReason,
		"SELECT revocation_reason FROM revoked_certificates WHERE fingerprint = :fingerprint",
		map[string]interface{}{
			"fingerprint": fingerprint,
		},
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "", nil
		}
		return false, "", err
	}
	return true, core.RevocationReasons[reovcationReason], nil
}

// CertificateExists checks if a certificate has already been added to the database
func (db *Database) CertificateExists(fingerprint []byte) (bool, error) {
	var count int
	err := db.m.SelectOne(
		&count,
		"SELECT count(fingerprint) FROM certificates WHERE fingerprint = :fingerprint",
		map[string]interface{}{
			"fingerprint": fingerprint,
		},
	)
	if err != nil {
		return false, err
	}
	return count > 0, err
}
