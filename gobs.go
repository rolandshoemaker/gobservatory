package main

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

	"gopkg.in/gorp.v1"

	"github.com/rolandshoemaker/gobservatory/core"
	"github.com/rolandshoemaker/gobservatory/external/asnFinder"
)

type rawSubmissionRequest struct {
	Certlist         []string `json:"certlist"`
	ServerIP         string   `json:"server_ip"`
	Domain           string   `json:"domain"`
	ASN              int      `json:"client_asn"`
	ChainFingerprint string   `json:"chain_fp"`
}

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

func (o *observatory) revoked(fingerprint []byte) (bool, string) {
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

func (o *observatory) submissionHandler(w http.ResponseWriter, r *http.Request) {
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
		if revoked, reason := o.revoked(fingerprint(c)); revoked {
			// Send message to client but don't skip submission
			revocationInfo = append(revocationInfo, revocationDescription{
				Serial: serialToString(c.SerialNumber),
				Reason: reason,
			})
		}
	}

	// Add submission to channel for workers to process
	o.submissions <- sr

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

func (o *observatory) parseCerts() error {
	for submission := range o.submissions {
		fmt.Println("PARSING SUBMISSION!")
		err := o.addCertificates(submission.Certs)
		if err != nil {
			// Log error don't return method so we can try to get everything in...
			fmt.Println(err)
		}
		err = o.addASN(submission.ASN, submission.ServerIP)
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

func (o *observatory) addCertificates(certs []*x509.Certificate) error {
	fmt.Println("ADDING CERTIFICATES!")
	fmt.Println(certs)
	intermediatePool := x509.NewCertPool()
	for _, cert := range certs {
		intermediatePool.AddCert(cert)
	}
	chainMap := make(map[string]certificateChain)
	for _, cert := range certs {
		// Check validity of certificate
		nssChains, err := cert.Verify(x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         o.nssPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return err
		}
		msChains, err := cert.Verify(x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         o.msPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return err
		}

		nssValidity := len(nssChains) > 0
		msValidity := len(msChains) > 0
		validity := nssValidity || msValidity
		transValidity := nssValidity && msValidity
		fmt.Println(nssValidity, msValidity, validity, transValidity)

		// Add NSS chains
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
		// Add MS chains
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
		// Check for trans valid chains
		for k, chain := range chainMap {
			if chain.MsValidity && chain.NssValidity {
				chain.TransValidity = true
				chainMap[k] = chain
			}
		}

		// Decompsoe certificate into all the different bits we want
	}

	// If no valid chains were produced add the current chain as invalid
	var chains []certificateChain
	if len(chainMap) == 0 {
		var chainBytes []byte
		for _, cert := range certs {
			chainBytes = append(chainBytes, cert.Raw...)
		}
		fingerprint := sha256.Sum256(chainBytes)
		chains = append(chains, certificateChain{
			Certs:       certs,
			Fingerprint: fingerprint[:],
			Validity:    false,
		})
	} else {
		for _, chain := range chainMap {
			chains = append(chains, chain)
		}
	}

	// Add all chains
	fmt.Println("ADDING CHAINS!")
	fmt.Println(chains)
	o.addChains(chains)

	return nil
}

func (o *observatory) addASN(asnNum int, ip net.IP) error {
	fmt.Println("ADDING ASN!")
	switch asnNum {
	case -2:
		asnName, asnNum, err := o.asnFinder.GetASN(ip)
		if err != nil {
			return err
		}
		// Do something with asnName
		fmt.Println(asnName, asnNum)
	}

	return nil
}

func (o *observatory) addChains(chains []certificateChain) {

}

type observatory struct {
	dbMap *gorp.DbMap

	nssPool   *x509.CertPool
	msPool    *x509.CertPool
	unionPool *x509.CertPool

	asnFinder *asnFinder.Finder

	submissions chan submissionRequest

	apiServer *http.Server
}

func newObservatory(apiServer, apiPort, whoisServer, whoisPort string) *observatory {
	obs := &observatory{}
	m := http.NewServeMux()
	m.HandleFunc("/submit_cert", obs.submissionHandler)
	obs.apiServer = &http.Server{Addr: net.JoinHostPort(apiServer, apiPort), Handler: m}
	obs.asnFinder = asnFinder.NewFinder(whoisServer, whoisPort)
	obs.submissions = make(chan submissionRequest)
	return obs
}

func fingerprint(cert *x509.Certificate) []byte {
	return nil
}

func main() {
	obs := newObservatory("localhost", "80", "v4.whois.cymru.com", "43")
	nssPool, err := core.PoolFromPEM("roots/nss_list.pem")
	if err != nil {
		fmt.Println(err)
		return
	}
	obs.nssPool = nssPool
	go func() {
		obs.parseCerts()
	}()
	err = obs.apiServer.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		return
	}
}
