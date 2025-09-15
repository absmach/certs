// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"

	"github.com/absmach/certs"
	"github.com/absmach/supermq/pkg/authn"
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

func (tm *tracingMiddleware) RenewCert(ctx context.Context, session authn.Session, serialNumber string) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "renew_cert")
	defer span.End()
	return tm.svc.RenewCert(ctx, session, serialNumber)
}

func (tm *tracingMiddleware) RevokeBySerial(ctx context.Context, session authn.Session, serialNumber string) error {
	ctx, span := tm.tracer.Start(ctx, "revoke_by_serial")
	defer span.End()
	return tm.svc.RevokeBySerial(ctx, session, serialNumber)
}

func (tm *tracingMiddleware) RevokeAll(ctx context.Context, session authn.Session, entityID string) error {
	ctx, span := tm.tracer.Start(ctx, "revoke_all")
	defer span.End()
	return tm.svc.RevokeAll(ctx, session, entityID)
}

func (tm *tracingMiddleware) RetrieveCAToken(ctx context.Context, session authn.Session) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "get_CA_download_token")
	defer span.End()
	return tm.svc.RetrieveCAToken(ctx, session)
}

func (tm *tracingMiddleware) IssueCert(ctx context.Context, session authn.Session, entityID, ttl string, ipAddrs []string, options certs.SubjectOptions) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "issue_cert")
	defer span.End()
	return tm.svc.IssueCert(ctx, session, entityID, ttl, ipAddrs, options)
}

func (tm *tracingMiddleware) ListCerts(ctx context.Context, session authn.Session, pm certs.PageMetadata) (certs.CertificatePage, error) {
	ctx, span := tm.tracer.Start(ctx, "list_certs")
	defer span.End()
	return tm.svc.ListCerts(ctx, session, pm)
}

func (tm *tracingMiddleware) ViewCert(ctx context.Context, session authn.Session, serialNumber string) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "view_cert")
	defer span.End()
	return tm.svc.ViewCert(ctx, session, serialNumber)
}

func (tm *tracingMiddleware) OCSP(ctx context.Context, session authn.Session, serialNumber string, ocspRequestDER []byte) ([]byte, error) {
	ctx, span := tm.tracer.Start(ctx, "ocsp")
	defer span.End()
	return tm.svc.OCSP(ctx, session, serialNumber, ocspRequestDER)
}

func (tm *tracingMiddleware) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "get_entity_id")
	defer span.End()
	return tm.svc.GetEntityID(ctx, serialNumber)
}

func (tm *tracingMiddleware) GenerateCRL(ctx context.Context, session authn.Session, caType certs.CertType) ([]byte, error) {
	ctx, span := tm.tracer.Start(ctx, "generate_crl")
	defer span.End()
	return tm.svc.GenerateCRL(ctx, session, caType)
}

func (tm *tracingMiddleware) GetChainCA(ctx context.Context, session authn.Session, token string) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "get_chain_ca")
	defer span.End()
	return tm.svc.GetChainCA(ctx, session, token)
}

func (tm *tracingMiddleware) IssueFromCSR(ctx context.Context, session authn.Session, entityID, ttl string, csr certs.CSR) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "issue_from_csr")
	defer span.End()
	return tm.svc.IssueFromCSR(ctx, session, entityID, ttl, csr)
}

func (tm *tracingMiddleware) IssueFromCSRInternal(ctx context.Context, entityID, ttl string, csr certs.CSR) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "issue_from_csr_internal")
	defer span.End()
	return tm.svc.IssueFromCSRInternal(ctx, entityID, ttl, csr)
}

func (tm *tracingMiddleware) GetCA(ctx context.Context) (certs.Certificate, error) {
	ctx, span := tm.tracer.Start(ctx, "get_ca")
	defer span.End()
	return tm.svc.GetCA(ctx)
}
