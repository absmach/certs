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
	"net"
	"os"
	"time"

	"github.com/absmach/certs/errors"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/ocsp"
	"gopkg.in/yaml.v2"
)

const (
	Organization                 = "AbstractMacines"
	emailAddress                 = "info@abstractmachines.rs"
	PrivateKeyBytes              = 2048
	RootCAValidityPeriod         = time.Hour * 24 * 365 // 365 days
	IntermediateCAVAlidityPeriod = time.Hour * 24 * 90  // 90 days
	certValidityPeriod           = time.Hour * 24 * 90  // 30 days
	rCertExpiryThreshold         = time.Hour * 24 * 30  // 30 days
	iCertExpiryThreshold         = time.Hour * 24 * 10  // 10 days
	downloadTokenExpiry          = time.Minute * 5
	configFile                   = "/config/config.yml"
)

type CertType int

const (
	RootCA CertType = iota
	IntermediateCA
	ClientCert
)

const (
	Root    = "RootCA"
	Inter   = "IntermediateCA"
	Client  = "ClientCert"
	Unknown = "Unknown"
)

func (c CertType) String() string {
	switch c {
	case RootCA:
		return Root
	case IntermediateCA:
		return Inter
	case ClientCert:
		return Client
	default:
		return Unknown
	}
}

func CertTypeFromString(s string) (CertType, error) {
	switch s {
	case Root:
		return RootCA, nil
	case Inter:
		return IntermediateCA, nil
	case Client:
		return ClientCert, nil
	default:
		return -1, errors.New("unknown cert type")
	}
}

type CA struct {
	Type         CertType
	Certificate  *x509.Certificate
	PrivateKey   *rsa.PrivateKey
	SerialNumber string
}

type CAConfig struct {
	CommonName         string   `yaml:"common_name"`
	Organization       []string `yaml:"organization"`
	OrganizationalUnit []string `yaml:"organizational_unit"`
	Country            []string `yaml:"country"`
	Province           []string `yaml:"province"`
	Locality           []string `yaml:"locality"`
	StreetAddress      []string `yaml:"street_address"`
	PostalCode         []string `yaml:"postal_code"`
	DNSNames           []string `yaml:"dns_names"`
	IPAddresses        []string `yaml:"ip_addresses"`
	ValidityPeriod     string   `yaml:"validity_period"`
}

type Config struct {
	CA CAConfig `yaml:"ca"`
}

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
)

type SubjectOptions struct {
	CommonName         string
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
}

type service struct {
	repo           Repository
	rootCA         *CA
	intermediateCA *CA
}

var _ Service = (*service)(nil)

func NewService(ctx context.Context, repo Repository) (Service, error) {
	var svc service

	config, err := LoadConfig(configFile)
	if err != nil {
		return &svc, err
	}

	svc.repo = repo
	if err := svc.loadCACerts(ctx); err != nil {
		return &svc, err
	}

	// check if root ca should be rotated
	rotateRoot := svc.shouldRotateCA(RootCA)
	if rotateRoot {
		if err := svc.rotateCA(ctx, RootCA, config); err != nil {
			return &svc, err
		}
	}

	rotateIntermediate := svc.shouldRotateCA(IntermediateCA)
	if rotateIntermediate {
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
	privKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return Certificate{}, err
	}

	if s.intermediateCA.Certificate == nil || s.intermediateCA.PrivateKey == nil {
		return Certificate{}, ErrIntermediateCANotFound
	}

	// Parse the TTL if provided, otherwise use the default certValidityPeriod.
	var validity time.Duration
	if ttl != "" {
		validity, err = time.ParseDuration(ttl)
		if err != nil {
			return Certificate{}, errors.Wrap(ErrMalformedEntity, err)
		}
	} else {
		validity = certValidityPeriod
	}

	subject := s.getSubject(options)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              append(s.intermediateCA.Certificate.DNSNames, ipAddrs...),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, s.intermediateCA.Certificate, &privKey.PublicKey, s.intermediateCA.PrivateKey)
	if err != nil {
		return Certificate{}, err
	}
	dbCert := Certificate{
		Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}),
		Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
		SerialNumber: template.SerialNumber.String(),
		EntityID:     entityID,
		ExpiryTime:   template.NotAfter,
		Type:         ClientCert,
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
	return cert, pem.EncodeToMemory(&pem.Block{Bytes: s.intermediateCA.Certificate.Raw, Type: "CERTIFICATE"}), nil
}

func (s *service) ListCerts(ctx context.Context, pm PageMetadata) (CertificatePage, error) {
	certPg, err := s.repo.ListCerts(ctx, pm)
	if err != nil {
		return CertificatePage{}, errors.Wrap(ErrViewEntity, err)
	}

	return certPg, nil
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

func (s *service) GetSigningCA(ctx context.Context, token string) (Certificate, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.intermediateCA.SerialNumber), nil
	}); err != nil {
		return Certificate{}, errors.Wrap(err, ErrMalformedEntity)
	}

	cert, err := s.repo.RetrieveCert(ctx, s.intermediateCA.SerialNumber)
	if err != nil {
		return Certificate{}, errors.Wrap(ErrViewEntity, err)
	}
	return cert, nil
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (s *service) generateRootCA(ctx context.Context, config CAConfig) (*CA, error) {
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
		IPAddresses:           parseIPs(config.IPAddresses),
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
		Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
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

func (s *service) createIntermediateCA(ctx context.Context, rootCA *CA, config CAConfig) (*CA, error) {
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
		IPAddresses:           parseIPs(config.IPAddresses),
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

func (s *service) getSubject(options SubjectOptions) pkix.Name {
	subject := pkix.Name{
		CommonName: options.CommonName,
	}

	if len(options.Organization) > 0 {
		subject.Organization = options.Organization
	}
	if len(options.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit = options.OrganizationalUnit
	}
	if len(options.Country) > 0 {
		subject.Country = options.Country
	}
	if len(options.Province) > 0 {
		subject.Province = options.Province
	}
	if len(options.Locality) > 0 {
		subject.Locality = options.Locality
	}
	if len(options.StreetAddress) > 0 {
		subject.StreetAddress = options.StreetAddress
	}
	if len(options.PostalCode) > 0 {
		subject.PostalCode = options.PostalCode
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
		newRootCA, err := s.generateRootCA(ctx, config.CA)
		if err != nil {
			return err
		}
		s.rootCA = newRootCA
		newIntermediateCA, err := s.createIntermediateCA(ctx, newRootCA, config.CA)
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
		newIntermediateCA, err := s.createIntermediateCA(ctx, s.rootCA, config.CA)
		if err != nil {
			return err
		}
		s.intermediateCA = newIntermediateCA

	default:
		return ErrCertInvalidType
	}

	return nil
}

func (s *service) shouldRotateCA(ctype CertType) bool {
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
				return errors.New("failed to parse key PEM")
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
				return errors.New("failed to parse key PEM")
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

func parseIPs(ipStrings []string) []net.IP {
	var ips []net.IP
	for _, ipString := range ipStrings {
		if ip := net.ParseIP(ipString); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
