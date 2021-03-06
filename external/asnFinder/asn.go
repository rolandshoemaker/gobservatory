package asnFinder

import (
	"fmt"
	"net"
	"time"
)

const whoisProvider = "v4.whois.cymru.com"

// Finder is used to find ASN names and numbers
type Finder struct {
	d           *net.Dialer
	whoisServer string
}

// New returns a newly initialized Finder
func New(server string, port string, timeout, keepAlive time.Duration) *Finder {
	return &Finder{
		whoisServer: net.JoinHostPort(server, port),
		d: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: keepAlive,
		},
	}
}

// GetASN uses the WHOIS protocol to retreive the ASN of an IP address and is a
// little gross
func (f *Finder) GetASN(ip net.IP) (int, string, error) {
	// conn, err := f.d.Dial("tcp", f.whoisServer)
	// if err != nil {
	// 	return 0, "", err
	// }
	// _, err = conn.Write([]byte(fmt.Sprintf("%s\r\n", ip)))
	// if err != nil {
	// 	return 0, "", err
	// }
	//
	// bodyBuf := make([]byte, 4096)
	// _, err = conn.Read(bodyBuf)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return 0, "", err
	// }
	// lines := strings.Split(string(bodyBuf), "\n")
	// if len(lines) < 2 {
	// 	return 0, "", fmt.Errorf("Not enough information about address")
	// }
	// fields := strings.Split(lines[1], "|")
	// if len(fields) < 3 {
	// 	return 0, "", fmt.Errorf("Not enough information about address")
	// }
	// asnName := fields[2]
	// asnNum, err := strconv.Atoi(strings.Trim(fields[0], " "))
	// if err != nil {
	// 	return 0, "", err
	// }
	//
	// return asnNum, strings.Trim(asnName, " \n"), nil
	return 0, "", fmt.Errorf("Not enough information about address")

}
