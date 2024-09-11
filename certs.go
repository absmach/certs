// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto/x509"
	"time"
)

type Certificate struct {
	SerialNumber string    `json:"serial_number" db:"serial_number"`
	Certificate  []byte    `json:"certificate" db:"certificate"`
	Key          []byte    `json:"key" db:"key"`
	Revoked      bool      `json:"revoked" db:"revoked"`
	ExpiryTime   time.Time `json:"expiry_time" db:"expiry_time"`
	EntityID     string    `json:"entity_id" db:"entity_id"`
	DownloadUrl  string    `json:"-" db:"-"`
}

type CertificatePage struct {
	PageMetadata
	Certificates []Certificate `json:"certificates"`
}

type PageMetadata struct {
	Total    uint64 `json:"total,omitempty" db:"total"`
	Offset   uint64 `json:"offset,omitempty" db:"offset"`
	Limit    uint64 `json:"limit,omitempty" db:"limit"`
	EntityID string `json:"entity_id,omitempty" db:"entity_id"`
}

type Service interface {
	// RenewCert renews a certificate from the database.
	RenewCert(ctx context.Context, serialNumber string) error

	// RevokeCert revokes a certificate from the database.
	RevokeCert(ctx context.Context, serialNumber string) error

	// RetrieveCert retrieves a certificate record from the database.
	RetrieveCert(ctx context.Context, token string, serialNumber string) (Certificate, []byte, error)

	// ViewCert retrieves a certificate record from the database.
	ViewCert(ctx context.Context, serialNumber string) (Certificate, error)

	// ListCerts retrieves the certificates from the database while applying filters.
	ListCerts(ctx context.Context, pm PageMetadata) (CertificatePage, error)

	// RetrieveCertDownloadToken retrieves a certificate download token.
	RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error)

	// IssueCert issues a certificate from the database.
	IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string) (string, error)

	// OCSP retrieves the OCSP response for a certificate.
	OCSP(ctx context.Context, serialNumber string) (*Certificate, int, *x509.Certificate, error)

	// GetEntityID retrieves the entity ID for a certificate.
	GetEntityID(ctx context.Context, serialNumber string) (string, error)
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
}
