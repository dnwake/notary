package cryptoservice

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
)

// GenerateCertificate generates an X509 Certificate from a template, given a GUN and validity interval.
func GenerateCertificate(rootKey data.PrivateKey, gun string, startTime, endTime time.Time) (*x509.Certificate, error) {
	return GenerateCertificate(signer, gun, startTime, endTime, nil)
}

// GenerateCertificate generates an X509 Certificate from a template, given a GUN and validity interval.
// The certificate is signed by ca if non-nil; otherwise it is self-signed.
func GenerateSignedCertificate(rootKey data.PrivateKey, gun string, startTime, endTime time.Time, ca *x509.Certificate) (*x509.Certificate, error) {
	signer := rootKey.CryptoSigner()
	if signer == nil {
		return nil, fmt.Errorf("key type not supported for Certificate generation: %s\n", rootKey.Algorithm())
	}

	return generateCertificate(signer, gun, startTime, endTime, ca)
}


func generateCertificate(signer crypto.Signer, gun string, startTime, endTime time.Time, ca *x509.Certificate) (*x509.Certificate, error) {
	template, err := trustmanager.NewCertificate(gun, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create the certificate template for: %s (%v)", gun, err)
	}

	var parent = template
        if ca != nil {
	   parent = ca
        }

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create the certificate for: %s (%v)", gun, err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the certificate for key: %s (%v)", gun, err)
	}

	return cert, nil
}
