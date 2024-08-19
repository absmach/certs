// Copyright (c) Ultraviolet
package certs

import (
	"context"
	"crypto/x509"
	"time"
)

type EntityType string

const (
	EntityTypeBackend EntityType = "backend"
)

type Certificate struct {
	SerialNumber string     `db:"serial_number"`
	Certificate  []byte     `db:"certificate"`
	Key          []byte     `db:"key"`
	Revoked      bool       `db:"revoked"`
	ExpiryDate   time.Time  `db:"expiry_date"`
	EntityType   EntityType `db:"entity_type"`
	EntityID     string     `db:"entity_id"`
	DownloadUrl  string     `db:"-"`
	CreatedBy    string     `db:"created_by"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedBy    *string     `db:"updated_by"`
	UpdatedAt    *time.Time  `db:"updated_at"`
}

type CertificatePage struct {
	Certificates []Certificate `json:"certificates"`
	PageMetadata
}

type PageMetadata struct {
	Total    uint64 `json:"total,omitempty" db:"total"`
	Offset   uint64 `json:"offset,omitempty" db:"offset"`
	Limit    uint64 `json:"limit,omitempty" db:"limit"`
	EntityID string `json:"entity_id,omitempty" db:"entity_id"`
}

//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines"
type Service interface {
	// RenewCert renews a certificate from the database.
	RenewCert(ctx context.Context, userId, serialNumber string) error

	// RevokeCert revokes a certificate from the database.
	RevokeCert(ctx context.Context, userId, serialNumber string) error

	// RetrieveCert retrieves a certificate record from the database.
	RetrieveCert(ctx context.Context, serialNumber string) (Certificate, []byte, error)

	// ListCerts retrieves the certificates from the database while applying filters.
	ListCerts(ctx context.Context, userId string, pm PageMetadata) (CertificatePage, error)

	// RetrieveCertDownloadToken retrieves a certificate download token.
	RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error)

	// IssueCert issues a certificate from the database.
	IssueCert(ctx context.Context, userId, entityID string, entityType EntityType, ipAddrs []string) (string, error)

	// OCSP retrieves the OCSP response for a certificate.
	OCSP(ctx context.Context, serialNumber string) (*Certificate, int, *x509.Certificate, error)

	// GetEntityID retrieves the entity ID for a certificate.
	GetEntityID(ctx context.Context, serialNumber string) (string, error)
}

//go:generate mockery --name Repository --output=./mocks --filename repository.go --quiet --note "Copyright (c) Abstract Machines"
type Repository interface {
	// CreateCert adds a certificate record to the database.
	CreateCert(ctx context.Context, cert Certificate) error

	// RetrieveCert retrieves a certificate record from the database.
	RetrieveCert(ctx context.Context, serialNumber string) (Certificate, error)

	// UpdateCert updates a certificate record in the database.
	UpdateCert(ctx context.Context, cert Certificate) error

	// ListCerts retrieves the certificates from the database while applying filters.
	ListCerts(ctx context.Context, userId string, pm PageMetadata) (CertificatePage, error)
}
