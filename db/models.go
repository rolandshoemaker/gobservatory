package db

import "time"

// ASN describes a ASN and when it was last observed
type ASN struct {
	Number   int       `db:"number"`
	Name     string    `db:"name"`
	LastSeen time.Time `db:"last_seen"`
}

// CertificateChainMeta describes a certificate chain and it's validity properties
type CertificateChainMeta struct {
	Fingerprint   []byte `db:"fingerprint"`
	Certs         int    `db:"certs"`
	NssValidity   bool   `db:"nss_valid"`
	MsValidity    bool   `db:"ms_valid"`
	TransValidity bool   `db:"trans_valid"`
	Validity      bool   `db:"valid"`
}

// RevokedCertificate describes a certificate that has been revoked by either
// OCSP or CRL
type RevokedCertificate struct {
	Fingerprint      []byte    `db:"fingerprint"`
	RevokedAt        time.Time `db:"revoked_at"`
	RevocationReason int       `db:"revocation_reason"`
	ByOCSP           bool      `db:"by_ocsp"`
	ByCRL            bool      `db:"by_crl"`
}

// Certificate describes a submitted certificate
type Certificate struct {
	Fingerprint             []byte    `db:"fingerprint"`
	Valid                   bool      `db:"valid"`
	CertVersion             uint8     `db:"version"`
	Root                    bool      `db:"root"`
	BasicConstraints        bool      `db:"basic_constraints"`
	NameConstraintsCritical bool      `db:"name_constraints_critical"`
	MaxPathLen              int       `db:"max_path_len"`
	MaxPathLenZero          bool      `db:"max_path_zero"`
	SignatureAlg            uint8     `db:"signature_alg"`
	Signature               []byte    `db:"signature"`
	NotBefore               time.Time `db:"not_before"`
	NotAfter                time.Time `db:"not_after"`
	Revoked                 bool      `db:"revoked"`

	LockCol int
}

// RawCertificate describes the raw form of a submitted certificate
type RawCertificate struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	DER                    []byte `db:"der"`
}

// AuthorityKeyID describes the authority key identifier of a submitted certificate
type AuthorityKeyID struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	KeyIdentifier          []byte `db:"key_identifier"`
}

// SubjectKeyID describes the subject key identifier of a submitted certificate
type SubjectKeyID struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	KeyIdentifier          []byte `db:"key_identifier"`
}

// KeyUsage describes the key usage of a submitted certificate
type KeyUsage struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	KeyUsage               uint8  `db:"usage"`
}

// RSAKey describes a RSA public key from a submitted certificate
type RSAKey struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	KeyFingerprint         []byte `db:"key_fingerprint"`
	ModulusSize            int    `db:"modulus_size"`
	Modulus                []byte `db:"modulus"`
	Exponent               int    `db:"exponent"`
}

// DSAKey describes a DSA public key from a submitted certificate
type DSAKey struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	KeyFingerprint         []byte `db:"key_fingerprint"`
	P                      []byte `db:"p"`
	Q                      []byte `db:"q"`
	G                      []byte `db:"g"`
	Y                      []byte `db:"y"`
}

// ECDSAKey describes a ECC public key from a submitted certificate
type ECDSAKey struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	KeyFingerprint         []byte `db:"key_fingerprint"`
	Curve                  string `db:"curve"`
	X                      []byte `db:"x"`
	Y                      []byte `db:"y"`
}

// DNSName describes a DNS name taken from a submitted certificate
type DNSName struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Name                   string `db:"name"`
	Wildcard               bool   `db:"wildcard"`
}

// IPAddress describes a IP address taken from a submitted certificate
type IPAddress struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	IP                     string `db:"ip"`
	AddressType            uint8  `db:"address_type"`
}

// EmailAddress describes a email address taken from a submitted certificate
type EmailAddress struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Email                  string `db:"email"`
}

// CommonName describes the common name of a submitted certificate
type CommonName struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Name                   string `db:"name"`
}

// Country describes a subject country tkane from a submitted certificate
type Country struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Country                string `db:"country"`
}

// Organization describes a subject organization taken from a submitted certificate
type Organization struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Organization           string `db:"organization"`
}

// OrganizationalUnit describes a subject organizational unit taken from a submitted certificate
type OrganizationalUnit struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	OrganizationalUnit     string `db:"organizational_unit"`
}

// Locality describes a subject locality taken from a submitted certificate
type Locality struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Locality               string `db:"locality"`
}

// Province describes a subject province taken from a submitted certificate
type Province struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Province               string `db:"province"`
}

// SubjectExtension describes a subject extension taken from a submitted certificate
type SubjectExtension struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Identifier             string `db:"identifier"`
	Value                  string `db:"value"`
}

// CertificateExtension describes a certificate extension taken from a submitted certificate
type CertificateExtension struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Identifier             string `db:"identifier"`
	Critical               bool   `db:"critical"`
	Value                  []byte `db:"value"`
}

// IssuingCertificateURL describes a issuing certificate url taken from a submitted certificate
type IssuingCertificateURL struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	URL                    string `db:"url"`
}

// OCSPEndpoint describes a OCSP server taken from a submitted certificate
type OCSPEndpoint struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Endpoint               string `db:"endpoint"`
}

// CRLEndpoint describes a CRL distribution point taken from a submitted certificate
type CRLEndpoint struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Endpoint               string `db:"endpoint"`
}

// ConstrainedName describes a DNS name constraint taken from a submitted certificate
type ConstrainedName struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Name                   string `db:"name"`
}

// PolicyIdentifier describes a policy identifier taken from a submitted certificate
type PolicyIdentifier struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	Identifier             string `db:"identifier"`
}

// Report describes a submission report for a certificate in a submitted chain
type Report struct {
	Source                 uint8     `db:"source"`
	CertificateFingerprint []byte    `db:"certificate_fingerprint"`
	ChainFingerprint       []byte    `db:"chain_fingerprint"`
	Leaf                   bool      `db:"leaf"`
	ServerIP               string    `db:"server_ip"`
	Domain                 string    `db:"domain"`
	ASNNumber              int       `db:"asn_number"`
	Submitted              time.Time `db:"submitted"`
}
