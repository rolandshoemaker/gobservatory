package submission

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rolandshoemaker/gobservatory/core"
	"github.com/rolandshoemaker/gobservatory/external/asnFinder"
	"gopkg.in/gorp.v1"
)

type submissionRequest struct {
	Certs            []*x509.Certificate
	ServerIP         net.IP
	Source           string
	Domain           string
	ASN              int
	ChainFingerprint []byte
}

type revocationDescription struct {
	Serial string
	Reason string `json:"revocationReason"`
}

func (a *API) revoked(fingerprint []byte) (bool, string) {
	return false, ""
}

func serialToString(serial *big.Int) string {
	return ""
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

	// Check if cert has been revoked
	var revocationInfo []revocationDescription
	for _, c := range sr.Certs {
		if revoked, reason := a.revoked(core.Fingerprint(c)); revoked {
			// Send message to client but don't skip submission
			revocationInfo = append(revocationInfo, revocationDescription{
				Serial: serialToString(c.SerialNumber),
				Reason: reason,
			})
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

func (a *API) ParseSubmissions() error {
	for submission := range a.submissions {
		fmt.Println("PARSING SUBMISSION!")
		err := a.addCertificates(submission.Certs)
		if err != nil {
			// Log error don't return method so we can try to get everything in...
			fmt.Println(err)
		}
		err = a.addASN(submission.ASN, submission.ServerIP)
		if err != nil {
			// Log error don't return method so we can try to get everything in
			fmt.Println(err)
		}
	}

	return nil
}

type certificateChain struct {
	Certs         []*x509.Certificate
	Fingerprint   []byte
	NssValidity   bool
	MsValidity    bool
	TransValidity bool
	Validity      bool
}

func (a *API) addCertificate(cert *x509.Certificate, nssValid, msValid bool) error {
	// Decompsoe certificate into all the different bits we want

	// Insert bits into database

	return nil
}

func (a *API) generateChains(certs []*x509.Certificate) []certificateChain {
	// Generated and add chains
	fmt.Println("GENERATING CHAINS!")
	chainMap := make(map[string]certificateChain)
	intermediatePool := x509.NewCertPool()
	for _, cert := range certs {
		intermediatePool.AddCert(cert)
	}
	nssValid := false
	msValid := false
	for _, cert := range certs {
		// Check NSS validity of certificate
		nssChains, err := cert.Verify(x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         a.nssPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			fmt.Println("NSS --", err)
		}
		// Check MS validity of certificate
		msChains, err := cert.Verify(x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         a.msPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			fmt.Println("MS --", err)
		}
		// XXX: This is, uh..., a little hacky :/
		if !nssValid {
			nssValid = len(nssChains) > 0
		}
		if !msValid {
			msValid = len(msChains) > 0
		}

		// Collect NSS chains
		for _, chain := range nssChains {
			var chainBytes []byte
			for _, cert := range chain {
				chainBytes = append(chainBytes, cert.Raw...)
			}
			fingerprint := sha256.Sum256(chainBytes)
			var present bool
			var existingChain certificateChain
			existingChain, present = chainMap[fmt.Sprintf("%x", fingerprint[:])]
			if !present {
				existingChain = certificateChain{Fingerprint: fingerprint[:]}
				existingChain.Certs = chain
				existingChain.Validity = true
			}
			existingChain.NssValidity = true
			chainMap[fmt.Sprintf("%x", fingerprint[:])] = existingChain
		}
		// Collect MS chains
		for _, chain := range msChains {
			var chainBytes []byte
			for _, cert := range chain {
				chainBytes = append(chainBytes, cert.Raw...)
			}
			fingerprint := sha256.Sum256(chainBytes)
			var present bool
			var existingChain certificateChain
			existingChain, present = chainMap[fmt.Sprintf("%x", fingerprint[:])]
			if !present {
				existingChain = certificateChain{Fingerprint: fingerprint[:]}
				existingChain.Certs = chain
				existingChain.Validity = true
			}
			existingChain.MsValidity = true
			chainMap[fmt.Sprintf("%x", fingerprint[:])] = existingChain
		}

		err = a.addCertificate(cert, nssValid, msValid)
		if err != nil {
			fmt.Println(err)
		}
	}

	// If no valid chains were produced check for trans-validity or add the chain
	// as invalid.
	if len(chainMap) == 0 {
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
			fmt.Println("TRANS --", err)
		}

		// Generate fingerprint and return
		var chainBytes []byte
		for _, cert := range certs {
			chainBytes = append(chainBytes, cert.Raw...)
		}
		fingerprint := sha256.Sum256(chainBytes)
		return []certificateChain{certificateChain{
			Certs:         certs,
			Fingerprint:   fingerprint[:],
			Validity:      trans,
			TransValidity: trans,
		}}
	}
	var chains []certificateChain
	for _, chain := range chainMap {
		chains = append(chains, chain)
	}
	return chains
}

func (a *API) addCertificates(certs []*x509.Certificate) error {
	fmt.Printf("ADDING [%d] CERTIFICATES!\n", len(certs))

	for _, cert := range certs {
		fmt.Printf("\t%s\n", cert.Subject.CommonName)
	}

	chains := a.generateChains(certs)

	// Add all chains
	a.addChains(chains)

	return nil
}

func (a *API) addASN(asnNum int, ip net.IP) error {
	fmt.Println("ADDING ASN!")
	switch asnNum {
	case -2:
		asnName, asnNum, err := a.asnFinder.GetASN(ip)
		if err != nil {
			return err
		}
		// Do something with asnName
		fmt.Printf("[ASN] Number: %d, Name: %s\n", asnName, asnNum)
	}

	return nil
}

func (a *API) addChains(chains []certificateChain) {
	fmt.Printf("ADDING [%d] CHAINS!\n", len(chains))
	for _, chain := range chains {
		fmt.Printf("[CHAIN] Fingerprint: %x, Certs: %d\n", chain.Fingerprint, len(chain.Certs))
		fmt.Printf("\t[VALIDITY] NSS: %v, MS: %v, Valid: %v, Trans-valid: %v\n", chain.NssValidity, chain.MsValidity, chain.Validity, chain.TransValidity)

	}
}

type API struct {
	dbMap *gorp.DbMap

	nssPool   *x509.CertPool
	msPool    *x509.CertPool
	transPool *x509.CertPool

	asnFinder *asnFinder.Finder

	submissions chan submissionRequest

	Server *http.Server
}

func NewAPI(nssPool, msPool *x509.CertPool, Server, apiPort string, asnFinder *asnFinder.Finder) *API {
	obs := &API{asnFinder: asnFinder}
	m := http.NewServeMux()
	m.HandleFunc("/submit_cert", obs.submissionHandler)
	obs.Server = &http.Server{Addr: net.JoinHostPort(Server, apiPort), Handler: m}
	obs.submissions = make(chan submissionRequest)
	return obs
}
