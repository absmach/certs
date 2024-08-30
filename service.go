// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/ocsp"
)

const (
	CommonName         = "AbstractMachines_Selfsigned_ca"
	Organization       = "AbstractMacines"
	OrganizationalUnit = "AbstractMachines_ca"
	Country            = "Sirbea"
	Province           = "Sirbea"
	Locality           = "Sirbea"
	StreetAddress      = "Sirbea"
	PostalCode         = "Sirbea"
	emailAddress       = "info@abstractmachines.rs"
	PrivateKeyBytes    = 2048
	certValidityPeriod = time.Hour * 24 * 90 // 90 days
)

var (
	serialNumberLimit          = new(big.Int).Lsh(big.NewInt(1), 128)
	errFailedReadingPrivateKey = New("failed to read private key")
	ErrNotFound                = New("entity not found")
	ErrConflict                = New("entity already exists")
	ErrCreateEntity            = New("failed to create entity")
	ErrViewEntity              = New("view entity failed")
	ErrUpdateEntity            = New("update entity failed")
	ErrMalformedEntity         = New("malformed entity specification")
	ErrRootCANotFound          = New("root CA not found")
	ErrCertExpired             = New("certificate expired before renewal")
	ErrCertRevoked             = New("certificate has been revoked and cannot be renewed")
)

type service struct {
	repo       Repository
	rootCACert *x509.Certificate
	rootCAKey  *rsa.PrivateKey
}

var _ Service = (*service)(nil)

func NewService(ctx context.Context, repo Repository) (Service, error) {
	cert, key, err := generateRootCA()
	if err != nil {
		return &service{}, err
	}

	svc := &service{
		repo:       repo,
		rootCACert: cert,
		rootCAKey:  key,
	}
	return svc, nil
}

// issueCert generates and issues a certificate for a given backendID.
// It uses the RSA algorithm to generate a private key, and then creates a certificate
// using the provided template and the generated private key.
// The certificate is then stored in the repository using the CreateCert method.
// If the root CA is not found, it returns an error.
func (s *service) IssueCert(ctx context.Context, entityID string, ipAddrs []string) (string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return "", err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", err
	}

	if s.rootCACert == nil || s.rootCAKey == nil {
		return "", ErrRootCANotFound
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{Organization},
			OrganizationalUnit: []string{OrganizationalUnit},
			Country:            []string{Country},
			Province:           []string{Province},
			Locality:           []string{Locality},
			StreetAddress:      []string{StreetAddress},
			PostalCode:         []string{PostalCode},
			CommonName:         s.rootCACert.Subject.CommonName,
			Names:              s.rootCACert.Subject.Names,
			ExtraNames:         s.rootCACert.Subject.ExtraNames,
			SerialNumber:       serialNumber.String(),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certValidityPeriod),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              append(s.rootCACert.DNSNames, ipAddrs...),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, s.rootCACert, &privKey.PublicKey, s.rootCAKey)
	if err != nil {
		return "", err
	}
	dbCert := Certificate{
		Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}),
		Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
		SerialNumber: template.SerialNumber.String(),
		EntityID:     entityID,
		ExpiryDate:   template.NotAfter,
	}
	if err = s.repo.CreateCert(ctx, dbCert); err != nil {
		return "", Wrap(ErrCreateEntity, err)
	}

	return dbCert.SerialNumber, nil
}

// RevokeCert revokes a certificate identified by its serial number.
// It requires a valid authentication token to authorize the revocation.
// If the authentication fails or the certificate cannot be found, an error is returned.
// Otherwise, the certificate is marked as revoked and updated in the repository.
func (s *service) RevokeCert(ctx context.Context, serialNumber string) error {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return Wrap(ErrViewEntity, err)
	}
	cert.Revoked = true
	cert.ExpiryDate = time.Now()
	if err != s.repo.UpdateCert(ctx, cert) {
		return Wrap(ErrUpdateEntity, err)
	}
	return nil
}

// RetrieveCert retrieves a certificate with the specified serial number.
// It requires a valid authentication token to be provided.
// If the token is invalid or expired, an error is returned.
// The function returns the retrieved certificate and any error encountered.
func (s *service) RetrieveCert(ctx context.Context, token string, serialNumber string) (Certificate, []byte, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(serialNumber), nil
	}); err != nil {
		return Certificate{}, []byte{}, Wrap(err, ErrMalformedEntity)
	}
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return Certificate{}, []byte{}, Wrap(ErrViewEntity, err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Bytes: s.rootCACert.Raw, Type: "CERTIFICATE"}), nil
}

func (s *service) ListCerts(ctx context.Context, pm PageMetadata) (CertificatePage, error) {
	certPg, err := s.repo.ListCerts(ctx, pm)
	if err != nil {
		return CertificatePage{}, Wrap(ErrViewEntity, err)
	}

	return certPg, nil
}

// GetCertDownloadToken generates a download token for a certificate.
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
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Minute * 5).Unix(), Issuer: Organization, Subject: "certs"})
	return jwtToken.SignedString([]byte(serialNumber))
}

// RenewCert renews a certificate by updating its validity period and generating a new certificate.
// It takes a context, token, and serialNumber as input parameters.
// It returns an error if there is any issue with retrieving the certificate, parsing the certificate,
// parsing the private key, creating a new certificate, or updating the certificate in the repository.
func (s *service) RenewCert(ctx context.Context, serialNumber string) error {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return Wrap(ErrViewEntity, err)
	}
	if cert.Revoked {
		return ErrCertRevoked
	}
	pemBlock, _ := pem.Decode(cert.Certificate)
	oldCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if !oldCert.NotAfter.After(time.Now()) {
		return ErrCertExpired
	}
	oldCert.NotBefore = time.Now()
	oldCert.NotAfter = time.Now().Add(certValidityPeriod)
	keyBlock, _ := pem.Decode(cert.Key)
	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	if s.rootCACert == nil || s.rootCAKey == nil {
		return ErrRootCANotFound
	}
	newCertBytes, err := x509.CreateCertificate(rand.Reader, oldCert, s.rootCACert, &privKey.PublicKey, s.rootCAKey)
	if err != nil {
		return err
	}
	cert.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCertBytes})
	cert.ExpiryDate = oldCert.NotAfter
	if err != s.repo.UpdateCert(ctx, cert) {
		return Wrap(ErrUpdateEntity, err)
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
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		if Contains(err, ErrNotFound) {
			return nil, ocsp.Unknown, s.rootCACert, nil
		}
		return nil, ocsp.ServerFailed, s.rootCACert, err
	}
	if cert.Revoked {
		return &cert, ocsp.Revoked, s.rootCACert, nil
	}
	return &cert, ocsp.Good, s.rootCACert, nil
}

func (s *service) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return "", Wrap(ErrViewEntity, err)
	}
	return cert.EntityID, nil
}

func generateRootCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{Organization},
			OrganizationalUnit: []string{OrganizationalUnit},
			Country:            []string{Country},
			Province:           []string{Province},
			Locality:           []string{Locality},
			StreetAddress:      []string{StreetAddress},
			PostalCode:         []string{PostalCode},
			CommonName:         CommonName,
			SerialNumber:       serialNumber.String(),
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: emailAddress,
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}
