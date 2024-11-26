// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"time"

	"github.com/absmach/certs/errors"
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

type Certificate struct {
	SerialNumber string    `db:"serial_number"`
	Certificate  []byte    `db:"certificate"`
	Key          []byte    `db:"key"`
	Revoked      bool      `db:"revoked"`
	ExpiryTime   time.Time `db:"expiry_time"`
	EntityID     string    `db:"entity_id"`
	Type         CertType  `db:"type"`
	DownloadUrl  string    `db:"-"`
}

type CertificatePage struct {
	PageMetadata
	Certificates []Certificate
}

type PageMetadata struct {
	Total    uint64 `json:"total,omitempty" db:"total"`
	Offset   uint64 `json:"offset,omitempty" db:"offset"`
	Limit    uint64 `json:"limit,omitempty" db:"limit"`
	EntityID string `json:"entity_id,omitempty" db:"entity_id"`
	Status   string `json:"status,omitempty" db:"status"`
}

type CSRMetadata struct {
	CommonName         string   `json:"common_name"`
	EntityID           string   `json:"entity_id"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	EmailAddresses     []string `json:"email_addresses"`
}

type CSR struct {
	ID           string    `json:"id" db:"id"`
	CSR          []byte    `json:"csr" db:"csr"`
	PrivateKey   []byte    `json:"private_key" db:"private_key"`
	EntityID     string    `json:"entity_id" db:"entity_id"`
	Status       string    `json:"status" db:"status"`
	SubmittedAt  time.Time `json:"submitted_at" db:"submitted_at"`
	ProcessedAt  time.Time `json:"processed_at" db:"processed_at"`
	SerialNumber string    `json:"serial_number" db:"serial_number"`
}

type CSRPage struct {
	PageMetadata
	CSRs []CSR
}

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

type Config struct {
	CommonName         string   `yaml:"common_name"`
	Organization       []string `yaml:"organization"`
	OrganizationalUnit []string `yaml:"organizational_unit"`
	Country            []string `yaml:"country"`
	Province           []string `yaml:"province"`
	Locality           []string `yaml:"locality"`
	StreetAddress      []string `yaml:"street_address"`
	PostalCode         []string `yaml:"postal_code"`
	DNSNames           []string `yaml:"dns_names"`
	IPAddresses        []net.IP `yaml:"ip_addresses"`
	ValidityPeriod     string   `yaml:"validity_period"`
}

type Service interface {
	// RenewCert renews a certificate from the database.
	RenewCert(ctx context.Context, serialNumber string) error

	// RevokeCert revokes a certificate from the database.
	RevokeCert(ctx context.Context, serialNumber string) error

	// RetrieveCert retrieves a certificate record from the database.
	RetrieveCert(ctx context.Context, token, serialNumber string) (Certificate, []byte, error)

	// ViewCert retrieves a certificate record from the database.
	ViewCert(ctx context.Context, serialNumber string) (Certificate, error)

	// ListCerts retrieves the certificates from the database while applying filters.
	ListCerts(ctx context.Context, pm PageMetadata) (CertificatePage, error)

	// RetrieveCertDownloadToken generates a certificate download token.
	// The token is needed to download the client certificate.
	RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error)

	// RetrieveCAToken generates a CA download and view token.
	// The token is needed to view and download the CA certificate.
	RetrieveCAToken(ctx context.Context) (string, error)

	// IssueCert issues a certificate from the database.
	IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string, option SubjectOptions, privKey ...*rsa.PrivateKey) (Certificate, error)

	// OCSP retrieves the OCSP response for a certificate.
	OCSP(ctx context.Context, serialNumber string) (*Certificate, int, *x509.Certificate, error)

	// GetEntityID retrieves the entity ID for a certificate.
	GetEntityID(ctx context.Context, serialNumber string) (string, error)

	// GenerateCRL creates cert revocation list.
	GenerateCRL(ctx context.Context, caType CertType) ([]byte, error)

	// GetChainCA retrieves the chain of CA i.e. root and intermediate cert concat together.
	GetChainCA(ctx context.Context, token string) (Certificate, error)

	// RemoveCert deletes a cert for a provided  entityID.
	RemoveCert(ctx context.Context, entityId string) error

	// CreateCSR creates a new Certificate Signing Request
	CreateCSR(ctx context.Context, metadata CSRMetadata, entityID string, privKey ...*rsa.PrivateKey) (CSR, error)

	// SignCSR processes a pending CSR and either approves or rejects it
	SignCSR(ctx context.Context, csrID string, approve bool) error

	// ListCSRs returns a list of CSRs based on filter criteria
	ListCSRs(ctx context.Context, entityID string, status string) (CSRPage, error)

	// RetrieveCSR retrieves a specific CSR by ID
	RetrieveCSR(ctx context.Context, csrID string) (CSR, error)
}

type Repository interface {
	// CreateCert adds a certificate record to the database.
	CreateCert(ctx context.Context, cert Certificate) error

	// RetrieveCert retrieves a certificate record from the database.
	RetrieveCert(ctx context.Context, serialNumber string) (Certificate, error)

	// UpdateCert updates a certificate record in the database.
	UpdateCert(ctx context.Context, cert Certificate) error

	// ListCerts retrieves the certificates from the database while applying filters.
	ListCerts(ctx context.Context, pm PageMetadata) (CertificatePage, error)

	// GetCAs retrieves rootCA and intermediateCA from database.
	GetCAs(ctx context.Context, caType ...CertType) ([]Certificate, error)

	// ListRevokedCerts retrieves revoked lists from database.
	ListRevokedCerts(ctx context.Context) ([]Certificate, error)

	// RemoveCert deletes cert from database.
	RemoveCert(ctx context.Context, entityId string) error
}

type CSRRepository interface {
	CreateCSR(context.Context, CSR) error
	UpdateCSR(context.Context, CSR) error
	ListCSRs(context.Context, PageMetadata) (CSRPage, error)
	RetrieveCSR(context.Context, string) (CSR, error)
}
