package db

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"strings"
	"time"

	"github.com/rolandshoemaker/gobservatory/core"
)

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
func (db *Database) AddChainMeta(chain *CertificateChainMeta) error {
	now := time.Now()
	_, err := db.m.Exec(
		`INSERT INTO chains (fingerprint, certs, first_seen, last_seen, nss_valid, ms_valid, trans_valid, valid, times_seen)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE last_seen=?, times_seen=VALUES(times_seen)+1`,
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
	now := time.Now()
	_, err := db.m.Exec(
		`INSERT INTO certificates (
		   fingerprint, key_fingerprint, valid, version, root, basic_constraints, name_constraints_critical,
		   max_path_len, max_path_zero, signature_alg, signature, not_before, not_after, revoked, key_usage,
		   subject_key_identifier, authority_key_identifier, serial, common_name, issuer_common_name,
		   times_seen, first_seen, last_seen
		 )
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE last_seen=?, times_seen=VALUES(times_seen)+1`,
		cert.Fingerprint,
		cert.KeyFingerprint,
		cert.Valid,
		cert.CertVersion,
		cert.Root,
		cert.BasicConstraints,
		cert.NameConstraintsCritical,
		cert.MaxPathLen,
		cert.MaxPathLenZero,
		cert.SignatureAlg,
		cert.Signature,
		cert.NotBefore,
		cert.NotAfter,
		cert.Revoked,
		cert.KeyUsage,
		cert.SubjectKeyIdentifier,
		cert.AuthorityKeyIdentifier,
		cert.Serial,
		cert.CommonName,
		cert.IssuerCommonName,
		1,   // times seen, if this is the first time
		now, // first seen, now
		now, // last seen, ...now
		now, // last seen, if a duplicate
	)
	if err != nil {
		return err
	}
	return nil
}

// AddRawCertificate adds a basic certificate outline that everything else links
// back to
func (db *Database) AddRawCertificate(rawCert *RawCertificate) error {
	return db.m.Insert(rawCert)
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

// AddRawKey adds a basic key outline that everything else links back to
func (db *Database) AddRawKey(rawKey *RawKey) error {
	return db.m.Insert(rawKey)
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
		addrType := uint8(0)
		if len(ip) == net.IPv6len {
			addrType = 1
		}
		err := db.m.Insert(&IPAddress{
			CertificateFingerprint: fingerprint,
			IP:          ip.String(),
			AddressType: addrType,
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

// AddSubjectExtensions adds subject extentions (really just subject fields that
// Golang doesnt' natively parse) from a certificate.
func (db *Database) AddSubjectExtensions(fingerprint []byte, extensions []pkix.AttributeTypeAndValue) error {
	for _, extension := range extensions {
		if _, present := core.ParsedSubjectOIDs[extension.Type.String()]; !present {
			if s, ok := extension.Value.(string); ok {
				err := db.m.Insert(&SubjectExtension{
					CertificateFingerprint: fingerprint,
					Identifier:             extension.Type.String(),
					Value:                  s,
				})
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// AddCertificateExtensions adds x509v3 extensions from a certificate
func (db *Database) AddCertificateExtensions(fingerprint []byte, extensions []pkix.Extension) error {
	for _, extension := range extensions {
		err := db.m.Insert(&CertificateExtension{
			CertificateFingerprint: fingerprint,
			Identifier:             extension.Id.String(),
			Critical:               extension.Critical,
			Value:                  extension.Value,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

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

// AddOCSPEndpoints adds OCSP endpoints taken from a certificate
func (db *Database) AddOCSPEndpoints(fingerprint []byte, endpoints []string) error {
	for _, endpoint := range endpoints {
		err := db.m.Insert(&OCSPEndpoint{
			CertificateFingerprint: fingerprint,
			Endpoint:               endpoint,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddCRLEndpoints adds CRL distribution endpoints taken from a certificate
func (db *Database) AddCRLEndpoints(fingerprint []byte, endpoints []string) error {
	for _, endpoint := range endpoints {
		err := db.m.Insert(&CRLEndpoint{
			CertificateFingerprint: fingerprint,
			Endpoint:               endpoint,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddConstrainedDNSNames adds constrained DNS names taken from a certificate
func (db *Database) AddConstrainedDNSNames(fingerprint []byte, names []string) error {
	for _, name := range names {
		err := db.m.Insert(&ConstrainedName{
			CertificateFingerprint: fingerprint,
			Name: name,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddPolicyIdentifiers adds policy identifiers taken from a certificate
func (db *Database) AddPolicyIdentifiers(fingerprint []byte, identifiers []asn1.ObjectIdentifier) error {
	for _, identifier := range identifiers {
		err := db.m.Insert(&PolicyIdentifier{
			CertificateFingerprint: fingerprint,
			Identifier:             identifier.String(),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AddReport adds a submission report to the database
func (db *Database) AddReport(report *Report) error {
	return db.m.Insert(report)
}
