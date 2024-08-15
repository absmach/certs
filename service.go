// Copyright (c) Ultraviolet
package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/ocsp"
)

const (
	Organization       = "AbstractMacines"
	PrivateKeyBytes    = 2048
	certValidityPeriod = time.Hour * 24 * 90 // 90 days
)

var (
	serialNumberLimit          = new(big.Int).Lsh(big.NewInt(1), 128)
	ErrCertExpired             = errors.New("certificate expired before renewal")
	ErrCertRevoked             = errors.New("certificate has been revoked and cannot be renewed")
	ErrRootCANotFound          = errors.New("root CA not found")
	errFailedReadingPrivateKey = errors.New("failed to read private key")
)

type service struct {
	repo       Repository
	auth       magistrala.AuthServiceClient
	idp        magistrala.IDProvider
	logger     *slog.Logger
	rootCACert *x509.Certificate
	rootCAKey  *rsa.PrivateKey
}

var _ Service = (*service)(nil)

func NewService(ctx context.Context, repo Repository, mgAuth magistrala.AuthServiceClient, idp magistrala.IDProvider, logger *slog.Logger, rootCACert, rootCAkey string) (Service, error) {
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	if rootCAkey != "" && rootCACert != "" {
		file, err := os.ReadFile(rootCACert)
		if err != nil {
			return &service{}, err
		}
		rootPem, _ := pem.Decode(file)
		cert, err = x509.ParseCertificate(rootPem.Bytes)
		if err != nil {
			return &service{}, err
		}
		file, err = os.ReadFile(rootCAkey)
		if err != nil {
			return &service{}, err
		}
		rootPem, _ = pem.Decode(file)

		privateKey, err := x509.ParsePKCS8PrivateKey(rootPem.Bytes)
		if err != nil {
			return &service{}, err
		}

		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return &service{}, errFailedReadingPrivateKey
		}
		key = rsaPrivateKey
	}

	svc := &service{
		repo:       repo,
		idp:        idp,
		auth:       mgAuth,
		logger:     logger,
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
func (s *service) IssueCert(ctx context.Context, token, entityID string, entityType EntityType, ipAddrs []string) (string, error) {
	res, err := s.identify(ctx, token)
	if err != nil {
		return "", err
	}

	if _, err := s.authorizeKind(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), auth.MemberPermission, auth.DomainType, res.GetDomainId()); err != nil {
		return "", err
	}

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
			Organization: []string{Organization},
			CommonName:   s.rootCACert.Subject.CommonName,
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
		EntityType:   entityType,
		ExpiryDate:   template.NotAfter,
	}
	if err = s.repo.CreateCert(ctx, dbCert); err != nil {
		return "", err
	}

	policies := magistrala.AddPoliciesReq{}
	policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
		Domain:      res.GetDomainId(),
		SubjectType: auth.DomainType,
		Subject:     res.GetDomainId(),
		Relation:    auth.DomainRelation,
		ObjectKind:  auth.NewCertKind,
		ObjectType:  auth.CertType,
		Object:      dbCert.SerialNumber,
		Permission:  auth.ViewPermission,
	})

	if _, err := s.auth.AddPolicies(ctx, &policies); err != nil {
		return "", err
	}

	return dbCert.SerialNumber, nil
}

// RevokeCert revokes a certificate identified by its serial number.
// It requires a valid authentication token to authorize the revocation.
// If the authentication fails or the certificate cannot be found, an error is returned.
// Otherwise, the certificate is marked as revoked and updated in the repository.
func (s *service) RevokeCert(ctx context.Context, token, serialNumber string) error {
	res, err := s.identify(ctx, token)
	if err != nil {
		return err
	}

	if _, err := s.authorizeKind(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), auth.MemberPermission, auth.DomainType, res.GetDomainId()); err != nil {
		return err
	}
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return err
	}
	cert.Revoked = true
	cert.ExpiryDate = time.Now()
	return s.repo.UpdateCert(ctx, cert)
}

// RetrieveCert retrieves a certificate with the specified serial number.
// It requires a valid authentication token to be provided.
// If the token is invalid or expired, an error is returned.
// The function returns the retrieved certificate and any error encountered.
func (s *service) RetrieveCert(ctx context.Context, token, serialNumber string) (Certificate, []byte, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{Issuer: Organization, Subject: "certs"}, func(token *jwt.Token) (interface{}, error) {
		return []byte(serialNumber), nil
	}); err != nil {
		return Certificate{}, []byte{}, errors.Wrap(err, errors.ErrMalformedEntity)
	}
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return Certificate{}, []byte{}, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Bytes: s.rootCACert.Raw, Type: "CERTIFICATE"}), nil
}

func (s *service) ListCerts(ctx context.Context, token string, pm PageMetadata) (CertificatePage, error) {
	res, err := s.identify(ctx, token)
	if err != nil {
		return CertificatePage{}, err
	}

	if _, err := s.authorizeKind(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), auth.MemberPermission, auth.DomainType, res.GetDomainId()); err != nil {
		return CertificatePage{}, err
	}
	certPg, err := s.repo.ListCerts(ctx, pm)
	if err != nil {
		return CertificatePage{}, err
	}

	return s.filterAllowedCertsOfDomainID(ctx, res.GetDomainId(), certPg)
}

// GetCertDownloadToken generates a download token for a certificate.
// It verifies the token and serial number, and returns a signed JWT token string.
// The token is valid for 5 minutes.
// Parameters:
//   - ctx: the context.Context object for the request
//   - token: the authentication token
//   - serialNumber: the serial number of the certificate
//
// Returns:
//   - string: the signed JWT token string
//   - error: an error if the authentication fails or any other error occurs
func (s *service) RetrieveCertDownloadToken(ctx context.Context, token, serialNumber string) (string, error) {
	res, err := s.identify(ctx, token)
	if err != nil {
		return "", err
	}

	if _, err := s.authorizeKind(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), auth.MemberPermission, auth.DomainType, res.GetDomainId()); err != nil {
		return "", err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Minute * 5).Unix(), Issuer: Organization, Subject: "certs"})
	return jwtToken.SignedString([]byte(serialNumber))
}

// RenewCert renews a certificate by updating its validity period and generating a new certificate.
// It takes a context, token, and serialNumber as input parameters.
// It returns an error if there is any issue with retrieving the certificate, parsing the certificate,
// parsing the private key, creating a new certificate, or updating the certificate in the repository.
func (s *service) RenewCert(ctx context.Context, token, serialNumber string) error {
	res, err := s.identify(ctx, token)
	if err != nil {
		return err
	}

	if _, err := s.authorizeKind(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), auth.MemberPermission, auth.DomainType, res.GetDomainId()); err != nil {
		return err
	}

	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return err
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
	return s.repo.UpdateCert(ctx, cert)
}

// identify returns the client ID associated with the provided token.
func (s *service) identify(ctx context.Context, token string) (*magistrala.IdentityRes, error) {
	req := &magistrala.IdentityReq{Token: token}
	res, err := s.auth.Identify(ctx, req)
	if err != nil {
		return nil, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	return res, nil
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
		if errors.Contains(err, svcerr.ErrNotFound) {
			return nil, ocsp.Unknown, s.rootCACert, nil
		}
		return nil, ocsp.ServerFailed, s.rootCACert, err
	}
	if cert.Revoked {
		return &cert, ocsp.Revoked, s.rootCACert, nil
	}
	return &cert, ocsp.Good, s.rootCACert, nil
}

func (s *service) authorizeKind(ctx context.Context, domainID, subjectType, subjectKind, subject, permission, objectType, object string) (string, error) {
	req := &magistrala.AuthorizeReq{
		Domain:      domainID,
		SubjectType: subjectType,
		SubjectKind: subjectKind,
		Subject:     subject,
		Permission:  permission,
		Object:      object,
		ObjectType:  objectType,
	}
	res, err := s.auth.Authorize(ctx, req)
	if err != nil {
		return "", err
	}
	if !res.GetAuthorized() {
		return "", svcerr.ErrAuthorization
	}
	return res.GetId(), nil
}

func (s *service) filterAllowedCertsOfDomainID(ctx context.Context, domainID string, certPg CertificatePage) (CertificatePage, error) {
	var certs []Certificate
	allowedIDs, err := s.listAllCertsOfDomainID(ctx, domainID)
	if err != nil {
		return CertificatePage{}, err
	}

	for _, cert := range certPg.Certificates {
		for _, id := range allowedIDs {
			if id == cert.SerialNumber {
				certs = append(certs, cert)
			}
		}
	}
	return CertificatePage{Certificates: certs}, nil
}

func (s *service) listAllCertsOfDomainID(ctx context.Context, domainID string) ([]string, error) {
	allowedIDs, err := s.auth.ListAllObjects(ctx, &magistrala.ListObjectsReq{
		SubjectType: auth.DomainType,
		Subject:     domainID,
		Permission:  auth.DomainRelation,
		ObjectType:  auth.CertType,
	})
	if err != nil {
		return []string{}, err
	}
	return allowedIDs.Policies, nil
}

func (s *service) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	cert, err := s.repo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return "", err
	}
	return cert.EntityID, nil
}
