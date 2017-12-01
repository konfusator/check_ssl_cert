// Copyright (C) 2017 Michael Fischer v. Mollard

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// The actual check is borrowed from https://github.com/timewasted/go-check-certs
// by Ryan Rogers
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/olorin/nagiosplugin"
	"time"
)

const (
	expireSoonFormat = "'%s' (S/N %X) expires in on %s (in %d days)"
	certOkFormat = "%s (S/N %X) valid until %s (%d days)"
	obsAlgorithmFormat = "'%s' (S/N %X) expires after the sunset date for its signature algorithm '%s'."
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}


// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

type certErrors struct {
	commonName string
	errs       []error
}


func main() {
	var (
		host     string
		warn     int64
		critical int64
		port     uint
		timeout  int64
	)

	flag.StringVar(&host, "H", "127.0.0.1", "Target host")
	flag.UintVar(&port, "p", 443, "Target port")
	flag.Int64Var(&warn, "w", 32, "days (warning)")
	flag.Int64Var(&critical, "c", 8, "days (critical)")
	flag.Int64Var(&timeout, "timeout", 10, "Plugin timeout")
	flag.Parse()

	check := nagiosplugin.NewCheck()

	// If we exit early or panic() we'll still output a result.
	defer check.Finish()


	// now for the timeout I don't really need the return values,
	// but it looks like something has to be written in the
	// channel
	c := make(chan int, 1)
	go func() { c <- check_ssl_cert(check, host, port, warn, critical) }()
	select {
	case <-c:
		return
	case <-time.After(time.Duration(timeout) * time.Second):
		check.AddResult(nagiosplugin.CRITICAL, fmt.Sprintf("Timeout after %d seconds", timeout))
		return
	}

}

func check_ssl_cert(check *nagiosplugin.Check, host string, port uint, warn int64, critical int64) int {

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), nil)
	if err != nil {
		check.AddResult(nagiosplugin.CRITICAL, fmt.Sprintf("error: %v", err))
		return int(nagiosplugin.CRITICAL)
	}
	defer conn.Close()

	timeNow := time.Now()

	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {

			expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
			if expiresIn  <= critical * 24  {
				check.AddResult(nagiosplugin.CRITICAL, fmt.Sprintf(expireSoonFormat, cert.Subject.CommonName, cert.SerialNumber, cert.NotAfter, expiresIn/24))
				return int(nagiosplugin.CRITICAL)
			} else if expiresIn  <= warn * 24   {
				check.AddResult(nagiosplugin.WARNING, fmt.Sprintf(expireSoonFormat, cert.Subject.CommonName, cert.SerialNumber, cert.NotAfter, expiresIn/24))
				return int(nagiosplugin.WARNING)
			} else {
				check.AddResult(nagiosplugin.OK, fmt.Sprintf(certOkFormat, cert.Subject.CommonName, cert.SerialNumber, cert.NotAfter, expiresIn/24))
			}

			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					check.AddResult(nagiosplugin.CRITICAL, fmt.Sprintf(obsAlgorithmFormat, cert.Subject.CommonName, cert.SerialNumber, alg.name))
				}
			}

		}
	}
	return int(nagiosplugin.UNKNOWN)
}
