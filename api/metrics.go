// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/metrics"
)

var _ certs.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     certs.Service
}

// MetricsMiddleware instruments core service by tracking request count and latency.
func MetricsMiddleware(svc certs.Service, counter metrics.Counter, latency metrics.Histogram) certs.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (mm *metricsMiddleware) RenewCert(ctx context.Context, token, cmpId string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "renew_certificate").Add(1)
		mm.latency.With("method", "renew_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RenewCert(ctx, token, cmpId)
}

func (mm *metricsMiddleware) RetrieveCert(ctx context.Context, serialNumber string) (certs.Certificate, []byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_certificate").Add(1)
		mm.latency.With("method", "get_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RetrieveCert(ctx, serialNumber)
}

func (mm *metricsMiddleware) RevokeCert(ctx context.Context, userId, serialNumber string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "revoke_certificate").Add(1)
		mm.latency.With("method", "revoke_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RevokeCert(ctx, userId, serialNumber)
}

func (mm *metricsMiddleware) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_certificate_download_token").Add(1)
		mm.latency.With("method", "get_certificate_download_token").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RetrieveCertDownloadToken(ctx, serialNumber)
}

func (mm *metricsMiddleware) IssueCert(ctx context.Context, userId, entityID string, entityType certs.EntityType, ipAddrs []string) (string, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "issue_certificate").Add(1)
		mm.latency.With("method", "issue_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.IssueCert(ctx, userId, entityID, entityType, ipAddrs)
}

func (mm *metricsMiddleware) ListCerts(ctx context.Context, userId string, pm certs.PageMetadata) (certs.CertificatePage, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_certificates").Add(1)
		mm.latency.With("method", "list_certificates").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.ListCerts(ctx, userId, pm)
}

func (mm *metricsMiddleware) OCSP(ctx context.Context, serialNumber string) (*certs.Certificate, int, *x509.Certificate, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "ocsp").Add(1)
		mm.latency.With("method", "ocsp").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.OCSP(ctx, serialNumber)
}

func (mm *metricsMiddleware) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_entity_id").Add(1)
		mm.latency.With("method", "get_entity_id").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.GetEntityID(ctx, serialNumber)
}
