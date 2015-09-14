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
	defer db.s.TimingDuration("submission.parsing.db.insert-update-latency.asns", time.Since(now), 1.0)
	_, err := db.m.Exec(
		`INSERT INTO asns (number, name, last_seen) VALUES(?, ?, ?)
		 ON DUPLICATE KEY UPDATE last_seen=?`,
		number,
		name,
		now,
		// Duplicate section of insert
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
	defer db.s.TimingDuration("submission.parsing.db.insert-update-latency.chains", time.Since(now), 1.0)
	_, err := db.m.Exec(
		`INSERT INTO chains (
			fingerprint, certs, nss_valid, ms_valid, trans_valid, valid, times_seen, first_seen, last_seen
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE last_seen=?, times_seen=VALUES(times_seen)+1`,
		chain.Fingerprint,
		chain.Certs,
		chain.NssValidity,
		chain.MsValidity,
		chain.TransValidity,
		chain.Validity,
		1,
		now,
		now,
		// Duplicate section of insert
		now,
	)
	return err
}

// AddCertificate adds a basic certificate outline that everything else links
// back to
func (db *Database) AddCertificate(cert *Certificate) error {
	now := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-update-latency.certificates", time.Since(now), 1.0)
	_, err := db.m.Exec(
		`INSERT INTO certificates (
		   size, fingerprint, key_fingerprint, key_alg, valid, version, root, expired, basic_constraints, name_constraints_critical,
		   max_path_len, max_path_zero, signature_alg, signature, not_before, not_after, key_usage,
		   subject_key_identifier, authority_key_identifier, serial, common_name, country, province, locality,
			 organization, organizational_unit, issuer_common_name, times_seen, first_seen, last_seen
		 )
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE last_seen=?, times_seen=VALUES(times_seen)+1`,
		// And now the long journey to the end of this insert begins, fraught with
		// terror and intrigue...
		cert.Size,
		cert.Fingerprint,
		cert.KeyFingerprint,
		cert.PublicKeyAlg,
		cert.Valid,
		cert.CertVersion,
		cert.Root,
		cert.Expired,
		cert.BasicConstraints,
		cert.NameConstraintsCritical,
		cert.MaxPathLen,
		cert.MaxPathLenZero,
		cert.SignatureAlg,
		cert.Signature,
		cert.NotBefore,
		cert.NotAfter,
		cert.KeyUsage,
		cert.SubjectKeyIdentifier,
		cert.AuthorityKeyIdentifier,
		cert.Serial,
		cert.CommonName,
		cert.Country,
		cert.Province,
		cert.Locality,
		cert.Organization,
		cert.OrganizationalUnit,
		cert.IssuerCommonName,
		1,   // times seen, if this is the first time
		now, // first seen, now
		now, // last seen, ...now
		// Duplicate section of insert
		now, // last seen, if a duplicate
	)
	return err
}

// AddRawCertificate adds a basic certificate outline that everything else links
// back to
func (db *Database) AddRawCertificate(rawCert *RawCertificate) error {
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.raw-certificates", time.Since(insertStarted), 1.0)

	return db.m.Insert(rawCert)
}

// AddPublicKey adds a RSA/DSA/ECDSA public key from a certificate or updates the
// last seen and times seen columns
func (db *Database) AddPublicKey(key *Key) error {
	now := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-update-latency.public-keys", time.Since(now), 1.0)
	_, err := db.m.Exec(
		`INSERT INTO public_keys (
			fingerprint, type, valid, rsa_modulus_size, rsa_modulus, rsa_exponent,
			dsa_p, dsa_q, dsa_g, dsa_y, ecdsa_curve, ecdsa_x, ecdsa_y, times_seen, first_seen, last_seen
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE last_seen=?, times_seen=VALUES(times_seen)+1`,
		key.Fingerprint,
		key.Type,
		key.Valid,
		key.RSAModulusSize,
		key.RSAModulus,
		key.RSAExponent,
		key.DSAP,
		key.DSAQ,
		key.DSAG,
		key.DSAY,
		key.ECDSACurve,
		key.ECDSAX,
		key.ECDSAY,
		1,
		now,
		now,
		// Duplicate section of insert
		now,
	)
	return err
}

// // AddRSAKey adds the RSA public key from a certificate
// func (db *Database) AddRSAKey(key *RSAKey) error {
// 	return db.m.Insert(key)
// }
//
// // AddDSAKey adds the DSA public key from a certificate
// func (db *Database) AddDSAKey(key *DSAKey) error {
// 	return db.m.Insert(key)
// }
//
// // AddECDSAKey adds the ECC public key from a certificate
// func (db *Database) AddECDSAKey(key *ECDSAKey) error {
// 	return db.m.Insert(key)
// }

// AddRawKey adds a basic key outline that everything else links back to
func (db *Database) AddRawKey(rawKey *RawKey) error {
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.raw-public-keys", time.Since(insertStarted), 1.0)

	return db.m.Insert(rawKey)
}

// AddDNSNames adds a set of DNS names from a certificate
func (db *Database) AddDNSNames(fingerprint []byte, names []string) error {
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.dns-names", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.ip-addresses", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.email-addresses", time.Since(insertStarted), 1.0)

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

// AddSubjectExtensions adds subject extentions (really just subject fields that
// Golang doesnt' natively parse) from a certificate.
func (db *Database) AddSubjectExtensions(fingerprint []byte, extensions []pkix.AttributeTypeAndValue) error {
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.subject-extensions", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.certificate-extensions", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.issuing-certificate-urls", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.ocsp-endpoints", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.crl-endpoints", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.constrained-dns-names", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.policy-identifiers", time.Since(insertStarted), 1.0)

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
	insertStarted := time.Now()
	defer db.s.TimingDuration("submission.parsing.db.insert-latency.reports", time.Since(insertStarted), 1.0)

	return db.m.Insert(report)
}
