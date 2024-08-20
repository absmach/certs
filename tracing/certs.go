// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
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

func (tm *tracingMiddleware) RenewCert(ctx context.Context, token, serialNumber string) error {
	ctx, span := tm.tracer.Start(ctx, "renew_cert")
	defer span.End()
	return tm.svc.RenewCert(ctx, token, serialNumber)
}

func (tm *tracingMiddleware) RevokeCert(ctx context.Context, token, serialNumber string) error {
	ctx, span := tm.tracer.Start(ctx, "revoke_cert")
	defer span.End()
	return tm.svc.RevokeCert(ctx, token, serialNumber)
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

func (tm *tracingMiddleware) IssueCert(ctx context.Context, userId, entityID string, entityType certs.EntityType, ipAddrs []string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "issue_cert")
	defer span.End()
	return tm.svc.IssueCert(ctx, userId, entityID, entityType, ipAddrs)
}

func (tm *tracingMiddleware) ListCerts(ctx context.Context, userId string, pm certs.PageMetadata) (certs.CertificatePage, error) {
	ctx, span := tm.tracer.Start(ctx, "list_certs")
	defer span.End()
	return tm.svc.ListCerts(ctx, userId, pm)
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
