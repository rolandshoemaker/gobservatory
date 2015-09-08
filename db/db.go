package db

import (
	"database/sql"

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
