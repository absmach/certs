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

func (mm *metricsMiddleware) RenewCert(ctx context.Context, cmpId string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "renew_certificate").Add(1)
		mm.latency.With("method", "renew_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RenewCert(ctx, cmpId)
}

func (mm *metricsMiddleware) RetrieveCert(ctx context.Context, token, serialNumber string) (certs.Certificate, []byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_certificate").Add(1)
		mm.latency.With("method", "get_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RetrieveCert(ctx, token, serialNumber)
}

func (mm *metricsMiddleware) RevokeCert(ctx context.Context, serialNumber string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "revoke_certificate").Add(1)
		mm.latency.With("method", "revoke_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RevokeCert(ctx, serialNumber)
}

func (mm *metricsMiddleware) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_certificate_download_token").Add(1)
		mm.latency.With("method", "get_certificate_download_token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.RetrieveCertDownloadToken(ctx, serialNumber)
}

func (mm *metricsMiddleware) RetrieveCAToken(ctx context.Context) (string, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_CA_token").Add(1)
		mm.latency.With("method", "get_CA_token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.RetrieveCAToken(ctx)
}

func (mm *metricsMiddleware) IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string, options certs.SubjectOptions) (certs.Certificate, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "issue_certificate").Add(1)
		mm.latency.With("method", "issue_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.IssueCert(ctx, entityID, ttl, ipAddrs, options)
}

func (mm *metricsMiddleware) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_certificates").Add(1)
		mm.latency.With("method", "list_certificates").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.ListCerts(ctx, pm)
}

func (mm *metricsMiddleware) RemoveCert(ctx context.Context, entityId string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "remove_certificate").Add(1)
		mm.latency.With("method", "remove_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.RemoveCert(ctx, entityId)
}

func (mm *metricsMiddleware) ViewCert(ctx context.Context, serialNumber string) (certs.Certificate, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_certificate").Add(1)
		mm.latency.With("method", "view_certificate").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewCert(ctx, serialNumber)
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

func (mm *metricsMiddleware) GenerateCRL(ctx context.Context, caType certs.CertType) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "generate_crl").Add(1)
		mm.latency.With("method", "generate_crl").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.GenerateCRL(ctx, caType)
}

func (mm *metricsMiddleware) GetChainCA(ctx context.Context, token string) (certs.Certificate, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_chain_ca").Add(1)
		mm.latency.With("method", "get_chain_ca").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mm.svc.GetChainCA(ctx, token)
}
