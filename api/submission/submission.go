package submission

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
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
	a.stats.Inc("submission.http.rate", 1, 1.0)
	start := time.Now()
	defer func() {
		a.stats.TimingDuration("submission.http.latency", time.Since(start), 1.0)
	}()
	// XXX: Debugging statements
	fmt.Println("REQUEST!")
	err := r.ParseForm()
	if err != nil {
		a.stats.Inc("submission.http.error-rate", 1, 1.0)
		fmt.Println(err)
		return
	}
	sr, err := formToRequest(r.Form)
	if err != nil {
		a.stats.Inc("submission.http.error-rate", 1, 1.0)
		fmt.Println(err)
		return
	}
	a.stats.Inc("submission.http.certificates.rate", int64(len(sr.Certs)), 1.0)
	sr.ClientIP = net.ParseIP(r.RemoteAddr)

	// Check if cert has been revoked
	var revocationInfo []revocationDescription
	for _, c := range sr.Certs {
		if revoked, reason, err := a.db.IsRevoked(core.Fingerprint(c.Raw)); revoked {
			// Send message to client but don't skip submission
			revocationInfo = append(revocationInfo, revocationDescription{
				Serial: core.BigIntToString(c.SerialNumber),
				Reason: reason,
			})
		} else if err != nil {
			// BAD, but continue on our way...
			a.stats.Inc("submission.http.error-rate", 1, 1.0)
			fmt.Println(err)
		}
	}

	// ...I know it's not reading but channels allow concurrent writes so this is
	// still safe
	a.sMu.RLock()
	defer a.sMu.RUnlock()
	// Add submission to channel for workers to process
	a.submissions <- sr

	if len(revocationInfo) > 0 {
		a.stats.Inc("submission.http.revoked-certificates-seen", int64(len(revocationInfo)), 1.0)
		revokedJSON, err := json.Marshal(revocationInfo)
		if err != nil {
			a.stats.Inc("submission.http.error-rate", 1, 1.0)
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
func (a *API) ParseSubmissions(wg *sync.WaitGroup) error {
	defer wg.Done()
	for submission := range a.submissions {
		a.stats.Gauge("submission.parsing.waiting", int64(len(a.submissions)), 1.0)
		// XXX: Debugging statements
		fmt.Println("PARSING SUBMISSION!")
		asnNum, err := a.addASN(submission.ASN, submission.ClientIP)
		if err != nil {
			// Log error don't return method so we can try to get everything in
			fmt.Println(err)
		}
		parsingStarted := time.Now()
		err = a.addCertificates(submission.Certs, asnNum, submission.ServerIP)
		if err != nil {
			// Log error don't return method so we can try to get everything in...
			fmt.Println(err)
		}
		a.stats.TimingDuration("submission.parsing.latency", time.Since(parsingStarted), 1.0)
		a.stats.Inc("submission.parsing.chains.rate", 1, 1.0)
	}

	return nil
}

func middleOfValdity(cert *x509.Certificate) time.Time {
	validityPeriod := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotBefore.Add(validityPeriod / 2)
}

func (a *API) generateChainMeta(certs []*x509.Certificate) (*db.CertificateChainMeta, bool, error) {
	// XXX: Debugging statements
	fmt.Println("GENERATING CHAINS!")
	intermediatePool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediatePool.AddCert(cert)
	}

	cert := certs[0]
	middle := middleOfValdity(cert)

	// Check NSS validity of certificate
	nssChains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         a.nssPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   middle,
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
		CurrentTime:   middle,
	})
	if err != nil {
		// XXX: Debugging statements
		fmt.Println("MS --", err)
	}

	// If no valid chains were produced check for trans-validity or add the chain
	// as invalid.
	nssValid := len(nssChains) > 0
	if nssValid {
		a.stats.Inc("submission.parsing.chains.nss-valid", 1, 1.0)
	}
	msValid := len(msChains) > 0
	if msValid {
		a.stats.Inc("submission.parsing.chains.ms-valid", 1, 1.0)
	}

	// Generate fingerprint and return
	var chainBytes []byte
	for _, cert := range certs {
		chainBytes = append(chainBytes, cert.Raw...)
	}
	fingerprint := sha256.Sum256(chainBytes)

	if nssValid || msValid {
		chain := &db.CertificateChainMeta{
			Certs:       len(certs),
			Fingerprint: fingerprint[:],
			Validity:    true,
			NssValidity: nssValid,
			MsValidity:  msValid,
		}
		a.stats.Inc("submission.parsing.chains.valid", 1, 1.0)
		return chain, true, nil
	}

	// Check for trans-validity
	trans := false
	transChains, err := certs[0].Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         a.transPool,
		CurrentTime:   middle,
	})
	if err != nil {
		fmt.Println(err)
	}
	if len(transChains) > 0 {
		trans = true
		a.stats.Inc("submission.parsing.chains.trans-valid", 1, 1.0)
	} else {
		a.stats.Inc("submission.parsing.chains.invalid", 1, 1.0)
	}

	return &db.CertificateChainMeta{
		Certs:         len(certs),
		Fingerprint:   fingerprint[:],
		Validity:      trans,
		TransValidity: trans,
	}, trans, nil
}

func (a *API) addCertificate(chainMeta *db.CertificateChainMeta, cert *x509.Certificate, valid, leaf bool, asnNum int, now time.Time, serverIP net.IP) error {
	// Check if certificate has already been added, if so no need to do work intensive
	// decomposition
	fingerprint := core.Fingerprint(cert.Raw)

	keyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	keyFingerprint := core.Fingerprint(keyDER)

	certModel := &db.Certificate{
		Size:                   len(cert.Raw),
		Fingerprint:            fingerprint,
		KeyFingerprint:         keyFingerprint,
		PublicKeyAlg:           uint8(cert.PublicKeyAlgorithm),
		Valid:                  valid,
		CertVersion:            uint8(cert.Version),
		Root:                   cert.IsCA,
		Expired:                time.Now().After(cert.NotAfter),
		BasicConstraints:       cert.BasicConstraintsValid,
		MaxPathLen:             cert.MaxPathLen,
		MaxPathLenZero:         cert.MaxPathLenZero,
		SignatureAlg:           uint8(cert.SignatureAlgorithm),
		Signature:              cert.Signature,
		NotBefore:              cert.NotBefore,
		NotAfter:               cert.NotAfter,
		SubjectKeyIdentifier:   cert.SubjectKeyId,
		AuthorityKeyIdentifier: cert.AuthorityKeyId,
		KeyUsage:               uint8(cert.KeyUsage),
		CommonName:             cert.Subject.CommonName,
		Serial:                 fmt.Sprintf("%X", cert.SerialNumber),
		IssuerCommonName:       cert.Issuer.CommonName,
		Country:                strings.Join(cert.Subject.Country, "; "),
		Province:               strings.Join(cert.Subject.Province, "; "),
		Locality:               strings.Join(cert.Subject.Locality, "; "),
		Organization:           strings.Join(cert.Subject.Organization, "; "),
		OrganizationalUnit:     strings.Join(cert.Subject.OrganizationalUnit, "; "),
	}

	exists, err := a.db.CertificateExists(fingerprint)
	if err != nil {
		return err
	}
	// Decompsoe certificate into all the different bits we want
	err = a.db.AddCertificate(certModel)
	if err != nil {
		return err
	}
	if exists {
		a.stats.Inc("submission.parsing.certificates.previously-seen", 1.0, 1)
		return nil
	}

	if time.Now().After(cert.NotAfter) {
		a.stats.Inc("submission.parsing.certificates.expired", 1, 1.0)
	}
	if valid {
		a.stats.Inc("submission.parsing.certificates.valid", 1, 1.0)
	} else {
		a.stats.Inc("submission.parsing.certificates.invalid", 1, 1.0)
	}

	if cert.IsCA && valid {
		a.stats.Inc("submission.parsing.certificates.roots.rate", 1, 1.0)
	}

	if sig, ok := core.SignatureAlgorithms[cert.SignatureAlgorithm]; ok {
		a.stats.Inc(fmt.Sprintf("submission.parsing.certificates.signature-algorithm.%s", sig), 1, 1.0)
	}

	// XXX: All of the db.Add... operations below could be run concurrently to
	//      improve performance somewhat (MySQL might not like this too much,
	//      but my gut says InnoDB should be able to handle it).

	// Raw certificate because why not
	err = a.db.AddRawCertificate(&db.RawCertificate{
		CertificateFingerprint: fingerprint,
		DER: cert.Raw,
	})
	if err != nil {
		// Continue
		fmt.Println(err)
	}

	// Public key
	keyExists, err := a.db.KeyExists(keyFingerprint)
	if err != nil {
		return err
	}
	key := &db.Key{
		Fingerprint: keyFingerprint,
		Valid:       valid,
	}
	switch t := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		a.stats.Inc("submission.parsing.certificates.key-types.RSA", 1, 1.0)
		key.Type = uint8(x509.RSA)
		key.RSAModulusSize = int64(t.N.BitLen())
		key.RSAModulus = t.N.Bytes()
		key.RSAExponent = int64(t.E)
	case *dsa.PublicKey:
		a.stats.Inc("submission.parsing.certificates.key-types.DSA", 1, 1.0)
		key.Type = uint8(x509.DSA)
		key.DSAP = t.P.Bytes()
		key.DSAQ = t.Q.Bytes()
		key.DSAG = t.G.Bytes()
		key.DSAY = t.Y.Bytes()
	case *ecdsa.PublicKey:
		a.stats.Inc("submission.parsing.certificates.key-types.ECDSA", 1, 1.0)
		key.Type = uint8(x509.ECDSA)
		key.ECDSACurve = t.Params().Name
		key.ECDSAX = t.X.Bytes()
		key.ECDSAY = t.Y.Bytes()
	}
	err = a.db.AddPublicKey(key)
	if err != nil {
		return err
	}
	if !keyExists {
		err = a.db.AddRawKey(&db.RawKey{
			KeyFingerprint: keyFingerprint,
			DER:            keyDER,
		})
		if err != nil {
			// Continue...
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

	// Extra subject sections
	err = a.db.AddSubjectExtensions(fingerprint, cert.Subject.Names)
	if err != nil {
		// Continue
		fmt.Println(err)
	}

	// Various identifiers and extensions
	err = a.db.AddPolicyIdentifiers(fingerprint, cert.PolicyIdentifiers)
	if err != nil {
		// Continue
		fmt.Println(err)
	}
	err = a.db.AddCertificateExtensions(fingerprint, cert.Extensions)
	if err != nil {
		// Continue
		fmt.Println(err)
	}
	err = a.db.AddIssuingCertificateURL(fingerprint, cert.IssuingCertificateURL)
	if err != nil {
		// Continue
		fmt.Println(err)
	}

	// Add report
	err = a.db.AddReport(&db.Report{
		Source:                 0,  // XXX: fix this...
		Domain:                 "", // XXX: fix this...
		ServerIP:               serverIP.String(),
		CertificateFingerprint: fingerprint,
		ChainFingerprint:       chainMeta.Fingerprint,
		Leaf:                   leaf,
		ASNNumber:              asnNum,
		Submitted:              now,
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *API) addCertificates(certs []*x509.Certificate, asnNum int, serverIP net.IP) error {
	// XXX: Debugging statements
	fmt.Printf("ADDING [%d] CERTIFICATES!\n", len(certs))

	chainMeta, valid, err := a.generateChainMeta(certs)
	if err != nil {
		return err
	}

	err = a.addChainMeta(chainMeta)
	if err != nil {
		return err
	}

	if exists, err := a.db.ChainExists(chainMeta.Fingerprint); err == nil && exists {
		a.stats.Inc("submission.parsing.chains.previously-seen", 1, 1.0)
		return nil
	}

	now := time.Now()
	for i, cert := range certs {
		err := a.addCertificate(chainMeta, cert, valid, (i == 0), asnNum, now, serverIP)
		if err != nil {
			// Log but don't break
			fmt.Println(err)
		}
		a.stats.Inc("submission.parsing.certificates.rate", 1, 1.0)
	}

	return nil
}

func (a *API) addASN(asnFlag int, ip net.IP) (int, error) {
	number := -1
	switch asnFlag {
	case -2: // XXX: ??? Check https everywhere / index.py to figure out whats needed
		// XXX: Debugging statements
		fmt.Println("ADDING ASN!")
		a.stats.Inc("submission.asn-finder.rate", 1, 1.0)
		asnFinderStarted := time.Now()
		number, name, err := a.asnFinder.GetASN(ip)
		if err != nil {
			return -1, err
		}
		a.stats.TimingDuration("submission.asn-finder.latency", time.Since(asnFinderStarted), 1.0)
		err = a.db.AddASN(number, name)
		if err != nil {
			return -1, err
		}
	}
	return number, nil
}

func (a *API) addChainMeta(chainMeta *db.CertificateChainMeta) (err error) {
	fmt.Printf("ADDING CHAIN METADATA!\n")
	// XXX: Debugging statements
	fmt.Printf("[CHAIN] Fingerprint: %x, Certs: %d, NSS: %v, MS: %v, Valid: %v, Trans-valid: %v\n", chainMeta.Fingerprint, chainMeta.Certs, chainMeta.NssValidity, chainMeta.MsValidity, chainMeta.Validity, chainMeta.TransValidity)
	return a.db.AddChainMeta(chainMeta)
}

// Serve starts the submission API either using HTTP or HTTPS
func (a *API) Serve(certPath, keyPath string) (err error) {
	m := http.NewServeMux()
	m.HandleFunc("/submit_cert", a.submissionHandler)
	srv := &http.Server{Addr: a.addr, Handler: m}

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		tlsConf := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		}
		srv.TLSConfig = tlsConf
	}
	l, err := net.Listen("tcp", a.addr)
	if err != nil {
		return err
	}
	a.listener = l
	defer l.Close()
	return srv.Serve(l)
}

// Shutdown gracefully shuts the server down, allowing any submissions remaining
// in a.submissions to be processed
func (a *API) Shutdown() error {
	err := a.listener.Close()
	if err != nil {
		// XXX: Continue and close the channel anyway, this may cause race induced
		// panics so uh... yeah it should be fixed
		fmt.Println(err)
	}
	a.sMu.Lock()
	defer a.sMu.Unlock()
	close(a.submissions)
	return err
}

// API defines the Observatory chain submission interface
type API struct {
	db        *db.Database
	asnFinder *asnFinder.Finder

	// This a somewhat lightweight use case for a sync.RWMutex but it achieves the
	// purpose and should be relatively performant
	sMu         *sync.RWMutex
	submissions chan submissionRequest

	nssPool   *x509.CertPool
	msPool    *x509.CertPool
	transPool *x509.CertPool

	addr     string
	listener net.Listener

	stats statsd.Statter
}

// New creates a new submission API
func New(nssPool, msPool, transPool *x509.CertPool, apiHost, apiPort string, asnFinder *asnFinder.Finder, db *db.Database, stats statsd.Statter) *API {
	return &API{
		asnFinder:   asnFinder,
		db:          db,
		nssPool:     nssPool,
		msPool:      msPool,
		transPool:   transPool,
		sMu:         new(sync.RWMutex),
		submissions: make(chan submissionRequest),
		addr:        net.JoinHostPort(apiHost, apiPort),
		stats:       stats,
	}
}
