package db

import (
	"database/sql"
	"time"

	"github.com/rolandshoemaker/gobservatory/core"

	"gopkg.in/gorp.v1"
)

// Database provides an interface to the MySQL database
type Database struct {
	m *gorp.DbMap
}

// New provides an initialized Database
func New() *Database {
	return &Database{}
}

// AddASN inserts or updates a ASN in the database
func (db *Database) AddASN(number int, name string) error {
	_, err := db.m.Exec(
		"INSERT INTO asns (number, name, last_seen) VALUES(:number, :name, :lastSeen) ON DUPLICATE KEY UPDATE last_seen=VALUE(:lastSeen)",
		map[string]interface{}{
			"number":   number,
			"name":     name,
			"lastSeen": time.Now(),
		},
	)
	if err != nil {
		return err
	}
	return nil
}

// AddChain inserts or updates a chain in the database
func (db *Database) AddChain(chain core.CertificateChain) error {
	return nil
}

// IsRevoked checks the revoked_certificates table to quickly check if a certificate
// has been revoked
func (db *Database) IsRevoked(fingerprint []byte) (bool, string, error) {
	var reovcationReason int
	err := db.m.SelectOne(
		&reovcationReason,
		"SELECT revocation_reason FROM revoked_certificates WHERE fingerprint=:fingerprint",
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