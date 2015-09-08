package submission

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rolandshoemaker/gobservatory/core"
	"github.com/rolandshoemaker/gobservatory/db"
	"github.com/rolandshoemaker/gobservatory/external/asnFinder"
)

type submissionRequest struct {
	Certs            []*x509.Certificate
	ServerIP         net.IP
	ClientIP         net.IP
	Source           string
	Domain           string
	ASN              int
	ChainFingerprint []byte
}

type revocationDescription struct {
	Serial string
	Reason string `json:"revocationReason"`
}

func formToRequest(args url.Values) (sr submissionRequest, err error) {
	var certs []string
	err = json.Unmarshal([]byte(strings.Replace(args.Get("certlist"), " ", "+", -1)), &certs)
	if err != nil {
		return sr, err
	}
	for _, b := range certs {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return sr, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// If there was some way of filtering out *obviously* misconstructed certs
			// information on what parsing failures we see here could be quite useful
			// to the Golang x509 team.
			return sr, err
		}
		sr.Certs = append(sr.Certs, cert)
	}
	sr.ServerIP = net.ParseIP(args.Get("server_ip"))
	sr.Source = args.Get("source")
	sr.Domain = args.Get("domain")
	sr.ASN, err = strconv.Atoi(args.Get("client_asn")) // XXX: This will fail when it isn't provided, is it required?
	sr.ChainFingerprint, err = base64.StdEncoding.DecodeString(args.Get("chain_fp"))
	return
}

func (a *API) submissionHandler(w http.ResponseWriter, r *http.Request) {
	// XXX: Debugging statements
	fmt.Println("REQUEST!")
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err)
		return
	}
	sr, err := formToRequest(r.Form)
	if err != nil {
		fmt.Println(err)
		return
	}
	sr.ClientIP = net.ParseIP(r.RemoteAddr)

	// Check if cert has been revoked
	var revocationInfo []revocationDescription
	for _, c := range sr.Certs {
		if revoked, reason, err := a.db.IsRevoked(core.Fingerprint(c)); revoked {
			// Send message to client but don't skip submission
			revocationInfo = append(revocationInfo, revocationDescription{
				Serial: core.BigIntToString(c.SerialNumber),
				Reason: reason,
			})
		} else if err != nil {
			// BAD
			fmt.Println(err)
			return
		}
	}

	// Add submission to channel for workers to process
	a.submissions <- sr

	if len(revocationInfo) > 0 {
		revokedJSON, err := json.Marshal(revocationInfo)
		if err != nil {
			// BAD
			fmt.Println(err)
			fmt.Fprintf(w, "Couldn't marshal revocation information: %s", err)
			return
		}
		// Set specific error code?
		fmt.Fprint(w, string(revokedJSON))
	}
}

// ParseSubmissions starts a parsing worker that chews through API.submissions
// and processes them, inserting the resulting information into the database
func (a *API) ParseSubmissions() error {
	for submission := range a.submissions {
		// XXX: Debugging statements
		fmt.Println("PARSING SUBMISSION!")
		asnNum, err := a.addASN(submission.ASN, submission.ClientIP)
		if err != nil {
			// Log error don't return method so we can try to get everything in
			fmt.Println(err)
		}
		err = a.addCertificates(submission.Certs, asnNum, submission.ServerIP)
		if err != nil {
			// Log error don't return method so we can try to get everything in...
			fmt.Println(err)
		}
	}

	return nil
}

func (a *API) generateChainMeta(certs []*x509.Certificate) (db.CertificateChainMeta, bool) {
	// XXX: Debugging statements
	fmt.Println("GENERATING CHAINS!")
	intermediatePool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediatePool.AddCert(cert)
	}
	cert := certs[0]
	// Check NSS validity of certificate
	nssChains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         a.nssPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		// XXX: Debugging statements
		fmt.Println("NSS --", err)
	}
	// Check MS validity of certificate
	msChains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         a.msPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		// XXX: Debugging statements
		fmt.Println("MS --", err)
	}

	// If no valid chains were produced check for trans-validity or add the chain
	// as invalid.
	nssValid := len(nssChains) > 0
	msValid := len(msChains) > 0
	if !nssValid && !msValid {
		trans := false
		// Check for trans-validity
		transChains, err := certs[0].Verify(x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         a.transPool,
		})
		if err != nil {
			fmt.Println(err)
		}
		if len(transChains) > 0 {
			trans = true
		} else if err != nil {
			// XXX: Debugging statements
			fmt.Println("TRANS --", err)
		}

		// Generate fingerprint and return
		var chainBytes []byte
		for _, cert := range certs {
			chainBytes = append(chainBytes, cert.Raw...)
		}
		fingerprint := sha256.Sum256(chainBytes)
		return db.CertificateChainMeta{
			Certs:         len(certs),
			Fingerprint:   fingerprint[:],
			Validity:      trans,
			TransValidity: trans,
		}, true
	}
	var chainBytes []byte
	for _, cert := range certs {
		chainBytes = append(chainBytes, cert.Raw...)
	}
	fingerprint := sha256.Sum256(chainBytes)
	chain := db.CertificateChainMeta{
		Certs:       len(certs),
		Fingerprint: fingerprint[:],
		Validity:    nssValid || msValid,
		NssValidity: nssValid,
		MsValidity:  msValid,
	}
	return chain, nssValid || msValid
}

func (a *API) addCertificate(chainMeta db.CertificateChainMeta, cert *x509.Certificate, valid, leaf bool, asnNum int, now time.Time, serverIP net.IP) error {
	// Check if certificate has already been added, if so no need to do work intensive
	// decomposition
	fingerprint := core.Fingerprint(cert)

	if exists, err := a.db.CertificateExists(fingerprint); err == nil && !exists {
		// Decompsoe certificate into all the different bits we want
		err = a.db.AddCertificate(&db.Certificate{
			Fingerprint:      fingerprint,
			Valid:            valid,
			CertVersion:      uint8(cert.Version),
			Root:             cert.IsCA,
			BasicConstraints: cert.BasicConstraintsValid,
			MaxPathLen:       cert.MaxPathLen,
			MaxPathLenZero:   cert.MaxPathLenZero,
			SignatureAlg:     uint8(cert.SignatureAlgorithm),
			Signature:        cert.Signature,
			NotBefore:        cert.NotBefore,
			NotAfter:         cert.NotAfter,
			Revoked:          false, // XXX: Without doing OCSP/CRL checks this'll have to do for now
		})
		if err != nil {
			return err
		}

		// Raw certificate because why not
		err = a.db.AddRawCertificate(&db.RawCertificate{
			CertificateFingerprint: fingerprint,
			DER: cert.Raw,
		})
		if err != nil {
			// Continue
			fmt.Println(err)
		}

		// Key IDs
		err = a.db.AddAuthorityKeyID(&db.AuthorityKeyID{
			CertificateFingerprint: fingerprint,
			KeyIdentifier:          cert.AuthorityKeyId,
		})
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddSubjectKeyID(&db.SubjectKeyID{
			CertificateFingerprint: fingerprint,
			KeyIdentifier:          cert.SubjectKeyId,
		})
		if err != nil {
			// Continue
			fmt.Println(err)
		}

		// Public key
		keyFingerprint, err := core.FingerprintKey(cert.PublicKey)
		if err != nil {
			// Continue
			fmt.Println(err)
		} else {
			switch t := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				err = a.db.AddRSAKey(&db.RSAKey{
					CertificateFingerprint: fingerprint,
					KeyFingerprint:         keyFingerprint,
					ModulusSize:            t.N.BitLen(), // XXX: FIX ME!
					Modulus:                t.N.Bytes(),
					Exponent:               t.E,
				})
			case *dsa.PublicKey:
				err = a.db.AddDSAKey(&db.DSAKey{
					CertificateFingerprint: fingerprint,
					KeyFingerprint:         keyFingerprint,
				})
			case *ecdsa.PublicKey:
				err = a.db.AddECDSAKey(&db.ECDSAKey{
					CertificateFingerprint: fingerprint,
					KeyFingerprint:         keyFingerprint,
					Curve:                  t.Params().Name,
					X:                      t.X.Bytes(),
					Y:                      t.Y.Bytes(),
				})
			}
			if err != nil {
				// Continue
				fmt.Println(err)
			}
		}

		// Names sections
		err = a.db.AddDNSNames(fingerprint, cert.DNSNames)
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddIPAddresses(fingerprint, cert.IPAddresses)
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddEmailAddresses(fingerprint, cert.EmailAddresses)
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddConstrainedDNSNames(fingerprint, cert.PermittedDNSDomains)
		if err != nil {
			// Continue
			fmt.Println(err)
		}

		// Remote revocation services
		err = a.db.AddOCSPEndpoints(fingerprint, cert.OCSPServer)
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddCRLEndpoints(fingerprint, cert.CRLDistributionPoints)
		if err != nil {
			// Continue
			fmt.Println(err)
		}

		// Subject sections
		err = a.db.AddCommonName(&db.CommonName{
			CertificateFingerprint: fingerprint,
			Name: cert.Subject.CommonName,
		})
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddCountries(fingerprint, cert.Subject.Country)
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddOrganizations(fingerprint, cert.Subject.Organization)
		err = a.db.AddOrganizationalUnits(fingerprint, cert.Subject.OrganizationalUnit)
		err = a.db.AddLocalities(fingerprint, cert.Subject.Locality)
		err = a.db.AddProvinces(fingerprint, cert.Subject.Province)

		// Various identifiers and extensions
		err = a.db.AddPolicyIdentifiers(fingerprint, cert.PolicyIdentifiers)
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		err = a.db.AddKeyUsage(&db.KeyUsage{
			CertificateFingerprint: fingerprint,
			KeyUsage:               uint8(cert.KeyUsage),
		})
		if err != nil {
			// Continue
			fmt.Println(err)
		}
		// AddSubjectExtensions
		// AddCertificateExtensions

	} else if err != nil {
		return err
	}

	// Add report
	return a.db.AddReport(&db.Report{
		Source:                 0,  // XXX: fix this...
		Domain:                 "", // XXX: fix this...
		ServerIP:               serverIP.String(),
		CertificateFingerprint: fingerprint,
		ChainFingerprint:       chainMeta.Fingerprint,
		Leaf:                   leaf,
		ASNNumber:              asnNum,
		Submitted:              now,
	})
}

func (a *API) addCertificates(certs []*x509.Certificate, asnNum int, serverIP net.IP) error {
	// XXX: Debugging statements
	fmt.Printf("ADDING [%d] CERTIFICATES!\n", len(certs))

	chainMeta, valid := a.generateChainMeta(certs)
	a.addChainMeta(chainMeta)

	now := time.Now()
	for i, cert := range certs {
		err := a.addCertificate(chainMeta, cert, valid, (i == 0), asnNum, now, serverIP)
		if err != nil {
			// Log but don't break
			fmt.Println(err)
		}
	}

	return nil
}

func (a *API) addASN(asnFlag int, ip net.IP) (int, error) {
	number := -1
	switch asnFlag {
	case -2: // XXX: ??? Check https everywhere / index.py to figure out whats needed
		// XXX: Debugging statements
		fmt.Println("ADDING ASN!")
		number, name, err := a.asnFinder.GetASN(ip)
		if err != nil {
			return -1, err
		}
		err = a.db.AddASN(number, name)
		if err != nil {
			return -1, err
		}
	}
	return number, nil
}

func (a *API) addChainMeta(chainMeta db.CertificateChainMeta) {
	fmt.Printf("ADDING CHAIN METADATA!\n")
	// XXX: Debugging statements
	fmt.Printf("[CHAIN] Fingerprint: %x, Certs: %d, NSS: %v, MS: %v, Valid: %v, Trans-valid: %v\n", chainMeta.Fingerprint, chainMeta.Certs, chainMeta.NssValidity, chainMeta.MsValidity, chainMeta.Validity, chainMeta.TransValidity)
	err := a.db.AddChainMeta(chainMeta)
	if err != nil {
		return
	}
}

// Serve starts the submission API either using HTTP or HTTPS
func (a *API) Serve(certPath, keyPath string) (err error) {
	if certPath != "" && keyPath != "" {
		err = a.Server.ListenAndServeTLS(certPath, keyPath)
	} else {
		err = a.Server.ListenAndServe()
	}
	if err != nil {
		return err
	}
	return nil
}

// API defines the Observatory chain submission interface
type API struct {
	db        *db.Database
	asnFinder *asnFinder.Finder

	submissions chan submissionRequest

	nssPool   *x509.CertPool
	msPool    *x509.CertPool
	transPool *x509.CertPool

	Server *http.Server
}

// New creates a new submission API
func New(nssPool, msPool *x509.CertPool, apiHost, apiPort string, asnFinder *asnFinder.Finder, db *db.Database) *API {
	obs := &API{asnFinder: asnFinder, db: db}
	m := http.NewServeMux()
	m.HandleFunc("/submit_cert", obs.submissionHandler)
	obs.Server = &http.Server{Addr: net.JoinHostPort(apiHost, apiPort), Handler: m}
	obs.submissions = make(chan submissionRequest)
	return obs
}
