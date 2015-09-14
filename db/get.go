package db

import (
	"database/sql"
	"time"

	"github.com/rolandshoemaker/gobservatory/core"
)

// IsRevoked checks the revoked_certificates table to quickly check if a certificate
// has been revoked
func (db *Database) IsRevoked(fingerprint []byte) (bool, string, error) {
	selectStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.select-latency.revoked-certificates", time.Since(selectStarted), 1.0)

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

// ChainExists checks if a chain has already been added to the database
func (db *Database) ChainExists(fingerprint []byte) (bool, error) {
	selectStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.select-latency.chains", time.Since(selectStarted), 1.0)

	var count int
	err := db.m.SelectOne(
		&count,
		"SELECT count(fingerprint) FROM chains WHERE fingerprint = :fingerprint",
		map[string]interface{}{
			"fingerprint": fingerprint,
		},
	)
	if err != nil {
		return false, err
	}
	return count > 0, err
}

// CertificateExists checks if a certificate has already been added to the database
func (db *Database) CertificateExists(fingerprint []byte) (bool, error) {
	selectStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.select-latency.certificates", time.Since(selectStarted), 1.0)

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

// KeyExists checks if a public key has already been added to the database
func (db *Database) KeyExists(fingerprint []byte) (bool, error) {
	selectStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.select-latency.public-keys", time.Since(selectStarted), 1.0)

	var count int
	err := db.m.SelectOne(
		&count,
		"SELECT count(key_fingerprint) FROM raw_keys WHERE key_fingerprint = :fingerprint",
		map[string]interface{}{
			"fingerprint": fingerprint,
		},
	)
	if err != nil {
		return false, err
	}
	return count > 0, err
}
