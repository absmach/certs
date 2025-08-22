// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

// Agent represents the PKI interface that all PKI implementations must satisfy.
type Agent interface {
	Issue(entityId, ttl string, ipAddrs []string, options SubjectOptions) (Certificate, error)
	View(serialNumber string) (Certificate, error)
	Revoke(serialNumber string) error
	ListCerts(pm PageMetadata) (CertificatePage, error)
	GetCA() ([]byte, error)
	GetCAChain() ([]byte, error)
	GetCRL() ([]byte, error)
	SignCSR(csr []byte, entityId, ttl string) (Certificate, error)
	Renew(serialNumber string, increment string) (Certificate, error)
}