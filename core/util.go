package core

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"runtime"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
)

// RevocationReasons maps reason codes to the text descriptions
var RevocationReasons = map[int]string{
	0: "unspecified",
	1: "keyCompromise",
	2: "cACompromise",
	3: "affiliationChanged",
	4: "superseded",
	5: "cessationOfOperation",
	6: "certificateHold",
	// 7 is unused
	8:  "removeFromCRL",
	9:  "privilegeWithdrawn",
	10: "aAcompromise",
}

// ParsedSubjectOIDs maps OIDs that Golang parses
var ParsedSubjectOIDs = map[string]bool{
	"2.5.4.6":  true, // Country
	"2.5.4.10": true, // Organization
	"2.5.4.11": true, // Organizational unit
	"2.5.4.3":  true, // Common name
	"2.5.4.5":  true, // Serial number
	"2.5.4.7":  true, // Locality
	"2.5.4.8":  true, // Province
}

// SignatureAlgorithms maps x509.SignatureAlgorithm's to their names
var SignatureAlgorithms = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA:      "MD2-RSA",
	x509.MD5WithRSA:      "MD5-RSA",
	x509.SHA1WithRSA:     "SHA1-RSA",
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.DSAWithSHA1:     "SHA1-DSA",
	x509.DSAWithSHA256:   "SHA256-DSA",
	x509.ECDSAWithSHA1:   "SHA1-ECDSA",
	x509.ECDSAWithSHA256: "SHA256-ECDSA",
	x509.ECDSAWithSHA384: "SHA384-ECDSA",
	x509.ECDSAWithSHA512: "SHA512-ECDSA",
}

// ServerConfig provides a simple reusable config most servers need
type ServerConfig struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

// PoolFromPEM constructs a x509.CertPool containing all the certificates in the
// PEM file at path
func PoolFromPEM(filename string) (*x509.CertPool, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(content); !ok {
		return nil, fmt.Errorf("Couldn't parse certificates from PEM file")
	}
	return pool, nil
}

// StringToFingerprint converts a string fingerprint to a byte fingerprint
func StringToFingerprint(fpStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(fpStr)

}

// Fingerprint creates MD5 and SHA1 hashes of the content and returns them concatenated
func Fingerprint(content []byte) []byte {
	md5Hash := md5.Sum(content)
	sha1Hash := sha1.Sum(content)
	return append(md5Hash[:], sha1Hash[:]...)
}

// BigIntToString converts a *big.Int to a hex string
func BigIntToString(bigInt *big.Int) string {
	return fmt.Sprintf("%X", bigInt)
}

// ProfileCmd runs forever, sending Go runtime statistics to StatsD.
func ProfileCmd(stats statsd.Statter) {
	c := time.Tick(1 * time.Second)
	for range c {
		var memoryStats runtime.MemStats
		runtime.ReadMemStats(&memoryStats)

		stats.Gauge("Gostats.Goroutines", int64(runtime.NumGoroutine()), 1.0)

		stats.Gauge("Gostats.Heap.Alloc", int64(memoryStats.HeapAlloc), 1.0)
		stats.Gauge("Gostats.Heap.Objects", int64(memoryStats.HeapObjects), 1.0)
		stats.Gauge("Gostats.Heap.Idle", int64(memoryStats.HeapIdle), 1.0)
		stats.Gauge("Gostats.Heap.InUse", int64(memoryStats.HeapInuse), 1.0)
		stats.Gauge("Gostats.Heap.Released", int64(memoryStats.HeapReleased), 1.0)

		// Calculate average and last and convert from nanoseconds to milliseconds
		gcPauseAvg := (int64(memoryStats.PauseTotalNs) / int64(len(memoryStats.PauseNs))) / 1000000
		lastGC := int64(memoryStats.PauseNs[(memoryStats.NumGC+255)%256]) / 1000000
		stats.Timing("Gostats.Gc.PauseAvg", gcPauseAvg, 1.0)
		stats.Gauge("Gostats.Gc.LastPauseTook", lastGC, 1.0)
		stats.Gauge("Gostats.Gc.NextAt", int64(memoryStats.NextGC), 1.0)
	}
}
