package main

import (
	"crypto/tls"
	"crypto/x509"
)

func fixtureClientTLS(pool *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
}
