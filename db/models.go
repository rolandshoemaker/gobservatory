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
	KeyFingerprint          []byte    `db:"key_fingerprint"`
	PublicKeyAlg            uint8     `db:"key_alg"`
	Size                    int       `db:"size"`
	Valid                   bool      `db:"valid"`
	CertVersion             uint8     `db:"version"`
	Root                    bool      `db:"root"`
	Expired                 bool      `db:"expired"`
	BasicConstraints        bool      `db:"basic_constraints"`
	NameConstraintsCritical bool      `db:"name_constraints_critical"`
	MaxPathLen              int       `db:"max_path_len"`
	MaxPathLenZero          bool      `db:"max_path_zero"`
	SignatureAlg            uint8     `db:"signature_alg"`
	Signature               []byte    `db:"signature"`
	NotBefore               time.Time `db:"not_before"`
	NotAfter                time.Time `db:"not_after"`
	SubjectKeyIdentifier    []byte    `db:"subject_key_identifier"`
	AuthorityKeyIdentifier  []byte    `db:"authority_key_identifier"`
	KeyUsage                uint8     `db:"key_usage"`
	CommonName              string    `db:"common_name"`
	Country                 string    `db:"country"`
	Province                string    `db:"province"`
	Locality                string    `db:"locality"`
	Organization            string    `db:"organization"`
	OrganizationalUnit      string    `db:"organizational_unit"`
	Serial                  string    `db:"serial"`
	IssuerCommonName        string    `db:"issuer_common_name"`

	LockCol int
}

// RawCertificate describes the raw form of a submitted certificate
type RawCertificate struct {
	CertificateFingerprint []byte `db:"certificate_fingerprint"`
	DER                    []byte `db:"der"`
}

// Key describes a RSA/DSA/ECDSA public key used in certificates
type Key struct {
	Fingerprint []byte `db:"fingerprint"`
	Type        uint8  `db:"type"`
	Valid       bool   `db:"valid"`
	// RSA parameters
	RSAModulusSize int64  `db:"rsa_modulus_size"`
	RSAModulus     []byte `db:"rsa_modulus"`
	RSAExponent    int64  `db:"rsa_exponent"`
	// DSA parameters
	DSAP []byte `db:"dsa_p"`
	DSAQ []byte `db:"dsa_q"`
	DSAG []byte `db:"dsa_g"`
	DSAY []byte `db:"dsa_y"`
	// ECDSA parameters
	ECDSACurve string `db:"ecdsa_curve"`
	ECDSAX     []byte `db:"ecdsa_x"`
	ECDSAY     []byte `db:"ecdsa_y"`
}

// // RSAKey describes a RSA public key from a submitted certificate
// type RSAKey struct {
// 	CertificateFingerprint []byte `db:"certificate_fingerprint"`
// 	KeyFingerprint         []byte `db:"key_fingerprint"`
// 	ModulusSize            int    `db:"modulus_size"`
// 	Modulus                []byte `db:"modulus"`
// 	Exponent               int    `db:"exponent"`
// 	Valid                  bool   `db:"valid"`
// }
//
// // DSAKey describes a DSA public key from a submitted certificate
// type DSAKey struct {
// 	CertificateFingerprint []byte `db:"certificate_fingerprint"`
// 	KeyFingerprint         []byte `db:"key_fingerprint"`
// 	P                      []byte `db:"p"`
// 	Q                      []byte `db:"q"`
// 	G                      []byte `db:"g"`
// 	Y                      []byte `db:"y"`
// 	Valid                  bool   `db:"valid"`
// }
//
// // ECDSAKey describes a ECC public key from a submitted certificate
// type ECDSAKey struct {
// 	CertificateFingerprint []byte `db:"certificate_fingerprint"`
// 	KeyFingerprint         []byte `db:"key_fingerprint"`
// 	Curve                  string `db:"curve"`
// 	X                      []byte `db:"x"`
// 	Y                      []byte `db:"y"`
// 	Valid                  bool   `db:"valid"`
// }

// RawKey describes the raw form of a submitted certificate
type RawKey struct {
	KeyFingerprint []byte `db:"key_fingerprint"`
	DER            []byte `db:"der"`
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
