package db

import (
	"database/sql"
	"net"
	"strings"
	"time"

	"github.com/rolandshoemaker/gobservatory/core"

	// MySQL driver import
	_ "github.com/rolandshoemaker/gobservatory/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	"github.com/rolandshoemaker/gobservatory/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

// Database provides an interface to the MySQL database
type Database struct {
	m *gorp.DbMap
}

// New provides an initialized Database
func New() (*Database, error) {
	db, err := sql.Open("mysql", "boulder@tcp(localhost:3306)/obs_draft_schema?parseTime=true&strict=true")
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}

	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}}
	dbmap.AddTableWithName(ASN{}, "asns")
	dbmap.AddTableWithName(RevokedCertificate{}, "revoked_certificates")
	dbmap.AddTableWithName(Certificate{}, "certificates")
	dbmap.AddTableWithName(RawCertificate{}, "raw_certificates")
	dbmap.AddTableWithName(AuthorityKeyID{}, "authority_key_ids")
	dbmap.AddTableWithName(SubjectKeyID{}, "subject_key_ids")
	dbmap.AddTableWithName(RSAKey{}, "rsa_keys")
	dbmap.AddTableWithName(DSAKey{}, "dsa_keys")
	dbmap.AddTableWithName(ECDSAKey{}, "ecdsa_keys")
	dbmap.AddTableWithName(DNSName{}, "dns_names")
	dbmap.AddTableWithName(IPAddress{}, "ip_addresses")
	dbmap.AddTableWithName(EmailAddress{}, "email_addresses")
	dbmap.AddTableWithName(CommonName{}, "common_names")
	dbmap.AddTableWithName(Country{}, "countries")
	dbmap.AddTableWithName(Organization{}, "organizations")
	dbmap.AddTableWithName(OrganizationalUnit{}, "organizational_units")
	dbmap.AddTableWithName(Locality{}, "localities")
	dbmap.AddTableWithName(Province{}, "provinces")
	dbmap.AddTableWithName(SubjectExtension{}, "subject_extensions")
	dbmap.AddTableWithName(CertificateExtension{}, "certificate_extensions")
	dbmap.AddTableWithName(IssuingCertificateURL{}, "issuing_certificate_urls")
	dbmap.AddTableWithName(OCSPEndpoint{}, "ocsp_endpoint")
	dbmap.AddTableWithName(CRLEndpoint{}, "crl_endpoint")
	dbmap.AddTableWithName(ConstrainedName{}, "constrained_names")
	dbmap.AddTableWithName(PolicyIdentifier{}, "policy_identifiers")
	dbmap.AddTableWithName(Report{}, "reports")

	// XXX: DEBUG
	// dbmap.TraceOn("SQL", log.New(os.Stdout, "[SQL] ", log.Flags()))

	return &Database{
		m: dbmap,
	}, nil
}

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

// AddASN inserts or updates a ASN in the database
func (db *Database) AddASN(number int, name string) error {
	now := time.Now()
	_, err := db.m.Exec(
		`INSERT INTO asns (number, name, last_seen) VALUES(?, ?, ?)
		 ON DUPLICATE KEY UPDATE last_seen=?`,
		number,
		name,
		now,
		now,
	)
	if err != nil {
		return err
	}
	return nil
}

// AddChainMeta inserts or updates a chain in the database
func (db *Database) AddChainMeta(chain CertificateChainMeta) error {
	now := time.Now()
	_, err := db.m.Exec(
		`INSERT INTO chains (fingerprint, certs, first_seen, last_seen, nss_valid, ms_valid, trans_valid, valid, count)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE last_seen=?, count=VALUES(count)+1`,
		chain.Fingerprint,
		chain.Certs,
		now,
		now,
		chain.NssValidity,
		chain.MsValidity,
		chain.TransValidity,
		chain.Validity,
		1,
		now,
	)
	if err != nil {
		return err
	}
	return nil
}

// AddCertificate adds a basic certificate outline that everything else links
// back to
func (db *Database) AddCertificate(cert *Certificate) error {
	return db.m.Insert(cert)
}

// AddRawCertificate adds a basic certificate outline that everything else links
// back to
func (db *Database) AddRawCertificate(rawCert *RawCertificate) error {
	return db.m.Insert(rawCert)
}

// AddAuthorityKeyID adds the authority key id from a certificate
func (db *Database) AddAuthorityKeyID(keyID *AuthorityKeyID) error {
	return db.m.Insert(keyID)
}

// AddSubjectKeyID adds the subject key id from a certificate
func (db *Database) AddSubjectKeyID(keyID *SubjectKeyID) error {
	return db.m.Insert(keyID)
}

// AddKeyUsage adds the key usage from a certificate
func (db *Database) AddKeyUsage(usage *KeyUsage) error {
	return db.m.Insert(usage)
}

// AddRSAKey adds the RSA public key from a certificate
func (db *Database) AddRSAKey(key *RSAKey) error {
	return db.m.Insert(key)
}

// AddDSAKey adds the DSA public key from a certificate
func (db *Database) AddDSAKey(key *DSAKey) error {
	return db.m.Insert(key)
}

// AddECDSAKey adds the ECC public key from a certificate
func (db *Database) AddECDSAKey(key *ECDSAKey) error {
	return db.m.Insert(key)
}

// AddDNSNames adds a set of DNS names from a certificate
func (db *Database) AddDNSNames(fingerprint []byte, names []string) error {
	for _, name := range names {
		err := db.m.Insert(&DNSName{
			CertificateFingerprint: fingerprint,
			Name:     name,
			Wildcard: strings.HasPrefix(name, "*."),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddIPAddresses adds a set of IP addresses from a certificate
func (db *Database) AddIPAddresses(fingerprint []byte, ips []net.IP) error {
	for _, ip := range ips {
		err := db.m.Insert(&IPAddress{
			CertificateFingerprint: fingerprint,
			IP: ip.String(),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddEmailAddresses adds a set of email addresses from a certificate
func (db *Database) AddEmailAddresses(fingerprint []byte, emails []string) error {
	for _, email := range emails {
		err := db.m.Insert(&EmailAddress{
			CertificateFingerprint: fingerprint,
			Email: email,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddCommonName adds the common name from a certificate
func (db *Database) AddCommonName(common *CommonName) error {
	return db.m.Insert(common)
}

// AddCountries adds subject countries from a certificate
func (db *Database) AddCountries(fingerprint []byte, countries []string) error {
	for _, country := range countries {
		err := db.m.Insert(&Country{
			CertificateFingerprint: fingerprint,
			Country:                country,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddOrganizations adds subject organizations from a certificate
func (db *Database) AddOrganizations(fingerprint []byte, organizations []string) error {
	for _, organization := range organizations {
		err := db.m.Insert(&Organization{
			CertificateFingerprint: fingerprint,
			Organization:           organization,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddOrganizationalUnits adds subject organizational units from a certificate
func (db *Database) AddOrganizationalUnits(fingerprint []byte, organizationalUnits []string) error {
	for _, organizationalUnit := range organizationalUnits {
		err := db.m.Insert(&OrganizationalUnit{
			CertificateFingerprint: fingerprint,
			OrganizationalUnit:     organizationalUnit,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddLocalities adds subject localities from a certificate
func (db *Database) AddLocalities(fingerprint []byte, localities []string) error {
	for _, locality := range localities {
		err := db.m.Insert(&Locality{
			CertificateFingerprint: fingerprint,
			Locality:               locality,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddProvinces adds subject provinces from a certificate
func (db *Database) AddProvinces(fingerprint []byte, provinces []string) error {
	for _, province := range provinces {
		err := db.m.Insert(&Province{
			CertificateFingerprint: fingerprint,
			Province:               province,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddSubjectExtensions

// AddCertificateExtensions

// AddIssuingCertificateURL adds issuing certificate URLs from a certificate
func (db *Database) AddIssuingCertificateURL(fingerprint []byte, urls []string) error {
	for _, url := range urls {
		err := db.m.Insert(&IssuingCertificateURL{
			CertificateFingerprint: fingerprint,
			URL: url,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddOCSPEndpoints

// AddCRLEndpoints

// AddConstrainedDNSNames

// AddPolicyIdentifiers

// AddReport adds a submission report to the database
func (db *Database) AddReport(report *Report) error {
	return db.m.Insert(report)
}
