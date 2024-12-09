// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/absmach/certs/errors"
	"github.com/golang-jwt/jwt"
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
	downloadTokenExpiry          = time.Minute * 5
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
)

type service struct {
	repo           Repository
	rootCA         *CA
	intermediateCA *CA
}

var _ Service = (*service)(nil)

func NewService(ctx context.Context, repo Repository, config *Config) (Service, error) {
	var svc service

	svc.repo = repo
	if err := svc.loadCACerts(ctx); err != nil {
		return &svc, err
	}

	// check if root ca should be rotated
	if svc.shouldRotate(RootCA) {
		if err := svc.rotateCA(ctx, RootCA, config); err != nil {
			return &svc, err
		}
	}

	if svc.shouldRotate(IntermediateCA) {
		if err := svc.rotateCA(ctx, IntermediateCA, config); err != nil {
			return &svc, err
		}
	}

	return &svc, nil
}

// issueCert generates and issues a certificate for a given backendID.
// It uses the RSA algorithm to generate a private key, and then creates a certificate
// using the provided template and the generated private key.
// The certificate is then stored in the repository using the CreateCert method.
// If the root CA is not found, it returns an error.
func (s *service) IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string, options SubjectOptions) (Certificate, error) {
	pKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return Certificate{}, err
	}

	if s.intermediateCA.Certificate == nil || s.intermediateCA.PrivateKey == nil {
		return Certificate{}, ErrIntermediateCANotFound
	}

	cert, err := s.issue(ctx, entityID, ttl, ipAddrs, options, pKey.Public(), pKey)
	if err != nil {
		return Certificate{}, err
	}

	return cert, nil
}

func (s *service) issue(ctx context.Context, entityID, ttl string, ipAddrs []string, options SubjectOptions, pubKey crypto.PublicKey, privKey crypto.PrivateKey) (Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return Certificate{}, err
	}

	subject := subjectFromOpts(options)
	if privKey != nil {
		switch privKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey:
			break
		default:
			return Certificate{}, errors.Wrap(ErrCreateEntity, ErrPrivKeyType)
		}
	}

	switch pubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, *ed25519.PublicKey:
		break
	default:
		return Certificate{}, errors.Wrap(ErrCreateEntity, ErrPubKeyType)
	}

	// Parse the TTL if provided, otherwise use the default certValidityPeriod.
	validity := certValidityPeriod
	if ttl != "" {
		validity, err = time.ParseDuration(ttl)
		if err != nil {
			return Certificate{}, errors.Wrap(ErrMalformedEntity, err)
		}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              append(s.intermediateCA.Certificate.DNSNames, ipAddrs...),
	}

	var privKeyBytes []byte
	var privKeyType string

	if privKey != nil {
		switch key := privKey.(type) {
		case *rsa.PrivateKey:
			privKeyBytes = x509.MarshalPKCS1PrivateKey(key)
			privKeyType = RSAPrivateKey
		case *ecdsa.PrivateKey:
			privKeyBytes, err = x509.MarshalPKCS8PrivateKey(key)
			privKeyType = ECPrivateKey
		case ed25519.PrivateKey:
			privKeyBytes, err = x509.MarshalPKCS8PrivateKey(key)
			privKeyType = PrivateKey
		}

		if err != nil {
			return Certificate{}, err
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, s.intermediateCA.Certificate, pubKey, s.intermediateCA.PrivateKey)
	if err != nil {
		return Certificate{}, err
	}

	dbCert := Certificate{
		SerialNumber: template.SerialNumber.String(),
		EntityID:     entityID,
		ExpiryTime:   template.NotAfter,
		Type:         ClientCert,
		Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
	}

	if privKeyBytes != nil {
		dbCert.Key = pem.EncodeToMemory(&pem.Block{Type: privKeyType, Bytes: privKeyBytes})
	}

	if err = s.repo.CreateCert(ctx, dbCert); err != nil {
		return Certificate{}, errors.Wrap(ErrCreateEntity, err)
	}

	return Certificate{
		Certificate:  dbCert.Certificate,
		SerialNumber: dbCert.SerialNumber,
		EntityID:     dbCert.EntityID,
		ExpiryTime:   dbCert.ExpiryTime,
		Revoked:      dbCert.Revoked,
		Type:         dbCert.Type,
	}, nil
}

// RevokeCert revokes a certificate identified by its serial number.
// It requires a valid authentication token to authorize the revocation.
// If the authentication fails or the certificate cannot be found, an error is returned.
// Otherwise, the certificate is marked as revoked and updated in the repository.
func (s *service) RevokeCert(ctx context.Context, serialNumber string) error {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return errors.Wrap(ErrViewEntity, err)
	}
	cert.Revoked = true
	cert.ExpiryTime = time.Now()
	if err != s.repo.UpdateCert(ctx, cert) {
		return errors.Wrap(ErrUpdateEntity, err)
	}
	return nil
}

// RetrieveCert retrieves a certificate with the specified serial number.
// It requires a valid authentication token to be provided.
// If the token is invalid or expired, an error is returned.
// The function returns the retrieved certificate and any error encountered.
func (s *service) RetrieveCert(ctx context.Context, token, serialNumber string) (Certificate, []byte, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(serialNumber), nil
	}); err != nil {
		return Certificate{}, []byte{}, errors.Wrap(err, ErrMalformedEntity)
	}
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
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
	certPg, err := s.repo.ListCerts(ctx, pm)
	if err != nil {
		return CertificatePage{}, errors.Wrap(ErrViewEntity, err)
	}

	return certPg, nil
}

func (s *service) RemoveCert(ctx context.Context, entityId string) error {
	return s.repo.RemoveCert(ctx, entityId)
}

func (s *service) ViewCert(ctx context.Context, serialNumber string) (Certificate, error) {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}
	return cert, nil
}

func (s *service) ViewCA(ctx context.Context) (Certificate, error) {
	cert, err := s.repo.RetrieveCert(ctx, s.intermediateCA.SerialNumber)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}
	return cert, nil
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
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{ExpiresAt: time.Now().Add(downloadTokenExpiry).Unix(), Issuer: Organization, Subject: "certs"})
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
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{ExpiresAt: time.Now().Add(downloadTokenExpiry).Unix(), Issuer: Organization, Subject: "certs"})
	token, err := jwtToken.SignedString([]byte(s.intermediateCA.SerialNumber))
	if err != nil {
		return "", errors.Wrap(ErrGetToken, err)
	}

	return token, nil
}

// RenewCert renews a certificate by updating its validity period and generating a new certificate.
// It takes a context, token, and serialNumber as input parameters.
// It returns an error if there is any issue with retrieving the certificate, parsing the certificate,
// parsing the private key, creating a new certificate, or updating the certificate in the repository.
func (s *service) RenewCert(ctx context.Context, serialNumber string) error {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return errors.Wrap(ErrViewEntity, err)
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
	if s.intermediateCA.Certificate == nil || s.intermediateCA.PrivateKey == nil {
		return ErrIntermediateCANotFound
	}
	newCertBytes, err := x509.CreateCertificate(rand.Reader, oldCert, s.intermediateCA.Certificate, &privKey.PublicKey, s.intermediateCA.PrivateKey)
	if err != nil {
		return err
	}
	cert.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCertBytes})
	cert.ExpiryTime = oldCert.NotAfter
	if err != s.repo.UpdateCert(ctx, cert) {
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
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		if errors.Contains(err, ErrNotFound) {
			return nil, ocsp.Unknown, s.intermediateCA.Certificate, nil
		}
		return nil, ocsp.ServerFailed, s.intermediateCA.Certificate, err
	}
	if cert.Revoked {
		return &cert, ocsp.Revoked, s.intermediateCA.Certificate, nil
	}
	return &cert, ocsp.Good, s.intermediateCA.Certificate, nil
}

func (s *service) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return "", errors.Wrap(ErrViewEntity, err)
	}
	return cert.EntityID, nil
}

func (s *service) GenerateCRL(ctx context.Context, caType CertType) ([]byte, error) {
	var ca *CA

	switch caType {
	case RootCA:
		if s.rootCA == nil {
			return nil, errors.New("root CA not initialized")
		}
		ca = s.rootCA
	case IntermediateCA:
		if s.intermediateCA == nil {
			return nil, errors.New("intermediate CA not initialized")
		}
		ca = s.intermediateCA
	default:
		return nil, errors.New("invalid CA type")
	}

	revokedCerts, err := s.repo.ListRevokedCerts(ctx)
	if err != nil {
		return nil, err
	}

	revokedCertificates := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, cert := range revokedCerts {
		serialNumber := new(big.Int)
		serialNumber.SetString(cert.SerialNumber, 10)
		revokedCertificates[i] = pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: cert.ExpiryTime,
		}
	}

	// CRL valid for 24 hours
	now := time.Now()
	expiry := now.Add(24 * time.Hour)

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(time.Now().UnixNano()),
		ThisUpdate:          now,
		NextUpdate:          expiry,
		RevokedCertificates: revokedCertificates,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.Certificate, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	return pemBytes, nil
}

func (s *service) GetChainCA(ctx context.Context, token string) (Certificate, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.intermediateCA.SerialNumber), nil
	}); err != nil {
		return Certificate{}, errors.Wrap(err, ErrMalformedEntity)
	}

	return s.getConcatCAs(ctx)
}

func (s *service) IssueFromCSR(ctx context.Context, entityID, ttl string, csr CSR) (Certificate, error) {
	block, _ := pem.Decode(csr.CSR)
	if block == nil {
		return Certificate{}, errors.New("failed to parse CSR PEM")
	}

	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrMalformedEntity, err)
	}

	if err := parsedCSR.CheckSignature(); err != nil {
		return Certificate{}, errors.Wrap(ErrMalformedEntity, err)
	}

	cert, err := s.issue(ctx, entityID, ttl, nil, SubjectOptions{
		CommonName:         parsedCSR.Subject.CommonName,
		Organization:       parsedCSR.Subject.Organization,
		OrganizationalUnit: parsedCSR.Subject.OrganizationalUnit,
		Country:            parsedCSR.Subject.Country,
		Province:           parsedCSR.Subject.Province,
		Locality:           parsedCSR.Subject.Locality,
		StreetAddress:      parsedCSR.Subject.StreetAddress,
		PostalCode:         parsedCSR.Subject.PostalCode,
	}, parsedCSR.PublicKey, nil)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrCreateEntity, err)
	}

	return cert, nil
}

func (s *service) getConcatCAs(ctx context.Context) (Certificate, error) {
	intermediateCert, err := s.repo.RetrieveCert(ctx, s.intermediateCA.SerialNumber)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}

	rootCert, err := s.repo.RetrieveCert(ctx, s.rootCA.SerialNumber)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}

	concat := string(intermediateCert.Certificate) + string(rootCert.Certificate)
	return Certificate{
		Certificate: []byte(concat),
		Key:         intermediateCert.Key,
		ExpiryTime:  intermediateCert.ExpiryTime,
	}, nil
}

func (s *service) generateRootCA(ctx context.Context, config Config) (*CA, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       config.Organization,
			OrganizationalUnit: config.OrganizationalUnit,
			Country:            config.Country,
			Province:           config.Province,
			Locality:           config.Locality,
			StreetAddress:      config.StreetAddress,
			PostalCode:         config.PostalCode,
			SerialNumber:       serialNumber.String(),
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: emailAddress,
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(RootCAValidityPeriod),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	if err := s.saveCA(ctx, cert, rootKey, RootCA); err != nil {
		return nil, err
	}

	return &CA{
		Type:         RootCA,
		Certificate:  cert,
		PrivateKey:   rootKey,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

func (s *service) saveCA(ctx context.Context, cert *x509.Certificate, privateKey *rsa.PrivateKey, CertType CertType) error {
	dbCert := Certificate{
		Key:          pem.EncodeToMemory(&pem.Block{Type: RSAPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
		Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		SerialNumber: cert.SerialNumber.String(),
		ExpiryTime:   cert.NotAfter,
		Type:         CertType,
	}
	if err := s.repo.CreateCert(ctx, dbCert); err != nil {
		return errors.Wrap(ErrCreateEntity, err)
	}
	return nil
}

func (s *service) createIntermediateCA(ctx context.Context, rootCA *CA, config Config) (*CA, error) {
	intermediateKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       config.Organization,
			OrganizationalUnit: config.OrganizationalUnit,
			Country:            config.Country,
			Province:           config.Province,
			Locality:           config.Locality,
			StreetAddress:      config.StreetAddress,
			PostalCode:         config.PostalCode,
			SerialNumber:       serialNumber.String(),
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: emailAddress,
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(IntermediateCAVAlidityPeriod),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCA.Certificate, &intermediateKey.PublicKey, rootCA.PrivateKey)
	if err != nil {
		return nil, err
	}

	intermediateCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	if err != s.saveCA(ctx, intermediateCert, intermediateKey, IntermediateCA) {
		return nil, err
	}

	intermediateCA := &CA{
		Type:         IntermediateCA,
		Certificate:  intermediateCert,
		PrivateKey:   intermediateKey,
		SerialNumber: serialNumber.String(),
	}

	return intermediateCA, nil
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

func (s *service) rotateCA(ctx context.Context, ctype CertType, config *Config) error {
	switch ctype {
	case RootCA:
		certificates, err := s.repo.GetCAs(ctx)
		if err != nil {
			return err
		}
		for _, cert := range certificates {
			if err := s.RevokeCert(ctx, cert.SerialNumber); err != nil {
				return err
			}
		}
		newRootCA, err := s.generateRootCA(ctx, *config)
		if err != nil {
			return err
		}
		s.rootCA = newRootCA
		newIntermediateCA, err := s.createIntermediateCA(ctx, newRootCA, *config)
		if err != nil {
			return err
		}
		s.intermediateCA = newIntermediateCA

	case IntermediateCA:
		certificates, err := s.repo.GetCAs(ctx, IntermediateCA)
		if err != nil {
			return err
		}
		for _, cert := range certificates {
			if err := s.RevokeCert(ctx, cert.SerialNumber); err != nil {
				return err
			}
		}
		newIntermediateCA, err := s.createIntermediateCA(ctx, s.rootCA, *config)
		if err != nil {
			return err
		}
		s.intermediateCA = newIntermediateCA

	default:
		return ErrCertInvalidType
	}

	return nil
}

func (s *service) shouldRotate(ctype CertType) bool {
	switch ctype {
	case RootCA:
		if s.rootCA == nil {
			return true
		}
		now := time.Now()

		// Check if the certificate is expiring soon i.e., within 30 days.
		if now.Add(rCertExpiryThreshold).After(s.rootCA.Certificate.NotAfter) {
			return true
		}
	case IntermediateCA:
		if s.intermediateCA == nil {
			return true
		}
		now := time.Now()

		// Check if the certificate is expiring soon i.e., within 10 days.
		if now.Add(iCertExpiryThreshold).After(s.intermediateCA.Certificate.NotAfter) {
			return true
		}
	}

	return false
}

func (s *service) loadCACerts(ctx context.Context) error {
	certificates, err := s.repo.GetCAs(ctx)
	if err != nil {
		return err
	}

	for _, c := range certificates {
		if c.Type == RootCA {
			rblock, _ := pem.Decode(c.Certificate)
			if rblock == nil {
				return errors.New("failed to parse certificate PEM")
			}

			rootCert, err := x509.ParseCertificate(rblock.Bytes)
			if err != nil {
				return err
			}
			rkey, _ := pem.Decode(c.Key)
			if rkey == nil {
				return ErrFailedParse
			}
			rootKey, err := x509.ParsePKCS1PrivateKey(rkey.Bytes)
			if err != nil {
				return err
			}
			s.rootCA = &CA{
				Type:         c.Type,
				Certificate:  rootCert,
				PrivateKey:   rootKey,
				SerialNumber: c.SerialNumber,
			}
		}

		iblock, _ := pem.Decode(c.Certificate)
		if iblock == nil {
			return errors.New("failed to parse certificate PEM")
		}
		if c.Type == IntermediateCA {
			interCert, err := x509.ParseCertificate(iblock.Bytes)
			if err != nil {
				return err
			}
			ikey, _ := pem.Decode(c.Key)
			if ikey == nil {
				return ErrFailedParse
			}
			interKey, err := x509.ParsePKCS1PrivateKey(ikey.Bytes)
			if err != nil {
				return err
			}
			s.intermediateCA = &CA{
				Type:         c.Type,
				Certificate:  interCert,
				PrivateKey:   interKey,
				SerialNumber: c.SerialNumber,
			}
		}
	}
	return nil
}
