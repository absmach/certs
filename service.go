// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/absmach/certs/errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ocsp"
)

const (
	Organization                 = "AbstractMacines"
	emailAddress                 = "info@abstractmachines.rs"
	PrivateKeyBytes              = 2048
	RootCAValidityPeriod         = time.Hour * 24 * 365 // 365 days
	IntermediateCAVAlidityPeriod = time.Hour * 24 * 90  // 90 days
	certValidityPeriod           = time.Hour * 24 * 30  // 30 days
	rCertExpiryThreshold         = time.Hour * 24 * 30  // 30 days
	iCertExpiryThreshold         = time.Hour * 24 * 10  // 10 days
	downloadTokenExpiry          = time.Minute * 5      // 5 minutes
	PrivateKey                   = "PRIVATE KEY"
	RSAPrivateKey                = "RSA PRIVATE KEY"
	ECPrivateKey                 = "EC PRIVATE KEY"
	PKCS8PrivateKey              = "PKCS8 PRIVATE KEY"
	EDPrivateKey                 = "ED25519 PRIVATE KEY"
)

var (
	serialNumberLimit         = new(big.Int).Lsh(big.NewInt(1), 128)
	ErrNotFound               = errors.New("entity not found")
	ErrConflict               = errors.New("entity already exists")
	ErrCreateEntity           = errors.New("failed to create entity")
	ErrViewEntity             = errors.New("view entity failed")
	ErrGetToken               = errors.New("failed to get token")
	ErrUpdateEntity           = errors.New("update entity failed")
	ErrMalformedEntity        = errors.New("malformed entity specification")
	ErrRootCANotFound         = errors.New("root CA not found")
	ErrIntermediateCANotFound = errors.New("intermediate CA not found")
	ErrCertExpired            = errors.New("certificate expired before renewal")
	ErrCertRevoked            = errors.New("certificate has been revoked and cannot be renewed")
	ErrCertInvalidType        = errors.New("invalid cert type")
	ErrInvalidLength          = errors.New("invalid length of serial numbers")
	ErrPrivKeyType            = errors.New("unsupported private key type")
	ErrPubKeyType             = errors.New("unsupported public key type")
	ErrFailedParse            = errors.New("failed to parse key PEM")
	ErrFailedCertCreation     = errors.New("failed to create certificate")
	ErrInvalidIP              = errors.New("invalid IP address")
)

type service struct {
	pki Agent
}

var _ Service = (*service)(nil)

func NewService(ctx context.Context, pki Agent) (Service, error) {
	var svc service

	svc.pki = pki

	return &svc, nil
}

// IssueCert generates and issues a certificate for a given entityID.
// It uses the PKI agent to generate and issue a certificate.
// The certificate is managed by OpenBao PKI internally.
func (s *service) IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string, options SubjectOptions) (Certificate, error) {
	cert, err := s.pki.Issue(entityID, ttl, ipAddrs, options)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	return cert, nil
}

// RevokeCert revokes a certificate identified by its serial number.
// It uses the PKI agent to revoke the certificate in OpenBao PKI.
func (s *service) RevokeCert(ctx context.Context, serialNumber string) error {
	err := s.pki.Revoke(serialNumber)
	if err != nil {
		return errors.Wrap(ErrUpdateEntity, err)
	}
	return nil
}

// RetrieveCert retrieves a certificate with the specified serial number.
// It requires a valid authentication token to be provided.
// If the token is invalid or expired, an error is returned.
// The function returns the retrieved certificate and any error encountered.
func (s *service) RetrieveCert(ctx context.Context, token, serialNumber string) (Certificate, []byte, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(serialNumber), nil
	}); err != nil {
		return Certificate{}, []byte{}, errors.Wrap(err, ErrMalformedEntity)
	}
	cert, err := s.pki.View(serialNumber)
	if err != nil {
		return Certificate{}, []byte{}, errors.Wrap(ErrViewEntity, err)
	}
	concat, err := s.getConcatCAs(ctx)
	if err != nil {
		return Certificate{}, []byte{}, errors.Wrap(ErrViewEntity, err)
	}

	return cert, concat.Certificate, nil
}

func (s *service) ListCerts(ctx context.Context, pm PageMetadata) (CertificatePage, error) {
	certPg, err := s.pki.ListCerts(pm)
	if err != nil {
		return CertificatePage{}, errors.Wrap(ErrViewEntity, err)
	}

	return certPg, nil
}

func (s *service) RemoveCert(ctx context.Context, serialNo string) error {
	err := s.pki.Revoke(serialNo)
	if err != nil {
		return errors.Wrap(ErrUpdateEntity, err)
	}
	return nil
}

func (s *service) ViewCert(ctx context.Context, serialNumber string) (Certificate, error) {
	cert, err := s.pki.View(serialNumber)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}
	return cert, nil
}

func (s *service) ViewCA(ctx context.Context) (Certificate, error) {
	caPEM, err := s.pki.GetCA()
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}

	if len(caPEM) == 0 {
		return Certificate{}, errors.New("CA certificate PEM is empty")
	}

	block, _ := pem.Decode(caPEM)
	if block == nil {
		caPreview := string(caPEM)
		if len(caPreview) > 100 {
			caPreview = caPreview[:100] + "..."
		}
		return Certificate{}, errors.New("failed to decode CA certificate PEM - received: " + caPreview)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}

	return Certificate{
		SerialNumber: cert.SerialNumber.String(),
		Certificate:  caPEM,
		Key:          nil,
		Revoked:      false,
		ExpiryTime:   cert.NotAfter,
		EntityID:     cert.Subject.CommonName,
		Type:         IntermediateCA,
	}, nil
}

// RetrieveCertDownloadToken generates a download token for a certificate.
// It verifies the token and serial number, and returns a signed JWT token string.
// The token is valid for 5 minutes.
// Parameters:
//   - ctx: the context.Context object for the request
//   - serialNumber: the serial number of the certificate
//
// Returns:
//   - string: the signed JWT token string
//   - error: an error if the authentication fails or any other error occurs
func (s *service) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(downloadTokenExpiry)), Issuer: Organization, Subject: "certs"})
	token, err := jwtToken.SignedString([]byte(serialNumber))
	if err != nil {
		return "", errors.Wrap(ErrGetToken, err)
	}

	return token, nil
}

// RetrieveCAToken generates a download token for a certificate.
// It verifies the token and serial number, and returns a signed JWT token string.
// The token is valid for 5 minutes.
// Parameters:
//   - ctx: the context.Context object for the request
//
// Returns:
//   - string: the signed JWT token string
//   - error: an error if the authentication fails or any other error occurs
func (s *service) RetrieveCAToken(ctx context.Context) (string, error) {
	caCert, err := s.ViewCA(ctx)
	if err != nil {
		return "", errors.Wrap(ErrGetToken, err)
	}
	
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(downloadTokenExpiry)), Issuer: Organization, Subject: "certs"})
	token, err := jwtToken.SignedString([]byte(caCert.SerialNumber))
	if err != nil {
		return "", errors.Wrap(ErrGetToken, err)
	}

	return token, nil
}

// RenewCert renews a certificate lease if it's still valid and renewable.
// This extends the TTL of an existing certificate without generating new keys.
func (s *service) RenewCert(ctx context.Context, serialNumber string) error {
	cert, err := s.pki.View(serialNumber)
	if err != nil {
		return errors.Wrap(ErrViewEntity, err)
	}
	if cert.Revoked {
		return ErrCertRevoked
	}
	block, _ := pem.Decode(cert.Certificate)
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if !x509Cert.NotAfter.After(time.Now().UTC()) {
		return ErrCertExpired
	}
	_, err = s.pki.Renew(serialNumber, "")
	if err != nil {
		return errors.Wrap(ErrUpdateEntity, err)
	}
	return nil
}

// OCSP retrieves the OCSP response for a certificate.
// It takes a context and serialNumber as input parameters.
// It returns the OCSP status, the root CA certificate, the root CA private key, and an error if any issue occurs.
// If the certificate is not found, it returns an OCSP status of Unknown.
// If the certificate is revoked, it returns an OCSP status of Revoked.
// If the server fails to retrieve the certificate, it returns an OCSP status of ServerFailed.
// Otherwise, it returns an OCSP status of Good.
func (s *service) OCSP(ctx context.Context, serialNumber string) (*Certificate, int, *x509.Certificate, error) {
	caCert, err := s.ViewCA(ctx)
	if err != nil {
		return nil, ocsp.ServerFailed, nil, err
	}
	
	block, _ := pem.Decode(caCert.Certificate)
	if block == nil {
		return nil, ocsp.ServerFailed, nil, errors.New("failed to decode CA certificate PEM")
	}
	
	x509CA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ocsp.ServerFailed, nil, errors.Wrap(ErrViewEntity, err)
	}

	cert, err := s.pki.View(serialNumber)
	if err != nil {
		if errors.Contains(err, ErrNotFound) {
			return nil, ocsp.Unknown, x509CA, nil
		}
		return nil, ocsp.ServerFailed, x509CA, err
	}
	if cert.Revoked {
		return &cert, ocsp.Revoked, x509CA, nil
	}
	return &cert, ocsp.Good, x509CA, nil
}

func (s *service) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	cert, err := s.pki.View(serialNumber)
	if err != nil {
		return "", errors.Wrap(ErrViewEntity, err)
	}
	return cert.EntityID, nil
}

func (s *service) GenerateCRL(ctx context.Context, caType CertType) ([]byte, error) {
	crl, err := s.pki.GetCRL()
	if err != nil {
		return nil, errors.Wrap(ErrFailedCertCreation, err)
	}
	return crl, nil
}

func (s *service) GetChainCA(ctx context.Context, token string) (Certificate, error) {
	caCert, err := s.ViewCA(ctx)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}
	
	if _, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(caCert.SerialNumber), nil
	}); err != nil {
		return Certificate{}, errors.Wrap(err, ErrMalformedEntity)
	}

	return s.getConcatCAs(ctx)
}

func (s *service) IssueFromCSR(ctx context.Context, entityID, ttl string, csr CSR) (Certificate, error) {
	cert, err := s.pki.SignCSR(csr.CSR, entityID, ttl)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	return cert, nil
}

func (s *service) RevokeCerts(ctx context.Context, entityID string) error {
	pm := PageMetadata{EntityID: entityID}
	certPage, err := s.pki.ListCerts(pm)
	if err != nil {
		return errors.Wrap(ErrViewEntity, err)
	}

	for _, cert := range certPage.Certificates {
		if err := s.pki.Revoke(cert.SerialNumber); err != nil {
			return errors.Wrap(ErrUpdateEntity, err)
		}
	}

	return nil
}

func (s *service) getConcatCAs(ctx context.Context) (Certificate, error) {
	caChain, err := s.pki.GetCAChain()
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}

	block, _ := pem.Decode(caChain)
	if block == nil {
		return Certificate{}, errors.New("failed to decode CA chain PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}

	return Certificate{
		Certificate: caChain,
		ExpiryTime:  cert.NotAfter,
	}, nil
}

func subjectFromOpts(opts SubjectOptions) pkix.Name {
	subject := pkix.Name{
		CommonName: opts.CommonName,
	}

	if len(opts.Organization) > 0 {
		subject.Organization = opts.Organization
	}
	if len(opts.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit = opts.OrganizationalUnit
	}
	if len(opts.Country) > 0 {
		subject.Country = opts.Country
	}
	if len(opts.Province) > 0 {
		subject.Province = opts.Province
	}
	if len(opts.Locality) > 0 {
		subject.Locality = opts.Locality
	}
	if len(opts.StreetAddress) > 0 {
		subject.StreetAddress = opts.StreetAddress
	}
	if len(opts.PostalCode) > 0 {
		subject.PostalCode = opts.PostalCode
	}

	return subject
}
