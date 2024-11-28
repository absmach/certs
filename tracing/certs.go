// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/absmach/certs"
	"go.opentelemetry.io/otel/trace"
)

var _ certs.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    certs.Service
}

// New returns a new auth service with tracing capabilities.
func New(svc certs.Service, tracer trace.Tracer) certs.Service {
	return &tracingMiddleware{tracer, svc}
}

func (tm *tracingMiddleware) RenewCert(ctx context.Context, serialNumber string) error {
	ctx, span := tm.tracer.Start(ctx, "renew_cert")
	defer span.End()
	return tm.svc.RenewCert(ctx, serialNumber)
}

func (tm *tracingMiddleware) RevokeCert(ctx context.Context, serialNumber string) error {
	ctx, span := tm.tracer.Start(ctx, "revoke_cert")
	defer span.End()
	return tm.svc.RevokeCert(ctx, serialNumber)
}

func (tm *tracingMiddleware) RetrieveCert(ctx context.Context, token, serialNumber string) (certs.Certificate, []byte, error) {
	ctx, span := tm.tracer.Start(ctx, "get_cert")
	defer span.End()
	return tm.svc.RetrieveCert(ctx, token, serialNumber)
}

func (tm *tracingMiddleware) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "get_cert_download_token")
	defer span.End()
	return tm.svc.RetrieveCertDownloadToken(ctx, serialNumber)
}

func (tm *tracingMiddleware) RetrieveCAToken(ctx context.Context) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "get_CA_download_token")
	defer span.End()
	return tm.svc.RetrieveCAToken(ctx)
}

func (tm *tracingMiddleware) IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string, options certs.SubjectOptions, privKey ...*rsa.PrivateKey) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "issue_cert")
	defer span.End()
	return tm.svc.IssueCert(ctx, entityID, ttl, ipAddrs, options, privKey...)
}

func (tm *tracingMiddleware) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
	ctx, span := tm.tracer.Start(ctx, "list_certs")
	defer span.End()
	return tm.svc.ListCerts(ctx, pm)
}

func (tm *tracingMiddleware) RemoveCert(ctx context.Context, entityId string) (err error) {
	ctx, span := tm.tracer.Start(ctx, "remove_cert")
	defer span.End()
	return tm.svc.RemoveCert(ctx, entityId)
}

func (s *tracingMiddleware) ViewCert(ctx context.Context, serialNumber string) (certs.Certificate, error) {
	ctx, span := s.tracer.Start(ctx, "view_cert")
	defer span.End()
	return s.svc.ViewCert(ctx, serialNumber)
}

func (tm *tracingMiddleware) OCSP(ctx context.Context, serialNumber string) (*certs.Certificate, int, *x509.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "ocsp")
	defer span.End()
	return tm.svc.OCSP(ctx, serialNumber)
}

func (tm *tracingMiddleware) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "get_entity_id")
	defer span.End()
	return tm.svc.GetEntityID(ctx, serialNumber)
}

func (tm *tracingMiddleware) GenerateCRL(ctx context.Context, caType certs.CertType) ([]byte, error) {
	ctx, span := tm.tracer.Start(ctx, "generate_crl")
	defer span.End()
	return tm.svc.GenerateCRL(ctx, caType)
}

func (tm *tracingMiddleware) GetChainCA(ctx context.Context, token string) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "get_chain_ca")
	defer span.End()
	return tm.svc.GetChainCA(ctx, token)
}

func (tm *tracingMiddleware) CreateCSR(ctx context.Context, metadata certs.CSRMetadata, privKey *rsa.PrivateKey) (certs.CSR, error) {
	ctx, span := tm.tracer.Start(ctx, "create_csr")
	defer span.End()
	return tm.svc.CreateCSR(ctx, metadata, privKey)
}

func (tm *tracingMiddleware) SignCSR(ctx context.Context, entityID, ttl string, csr certs.CSR) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "sign_csr")
	defer span.End()
	return tm.svc.SignCSR(ctx, entityID, ttl, csr)
}
