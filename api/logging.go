// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/certs"
)

var _ certs.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    certs.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc certs.Service, logger *slog.Logger) certs.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) RenewCert(ctx context.Context, serialNumber string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method renew_cert for cert %s took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RenewCert(ctx, serialNumber)
}

func (lm *loggingMiddleware) RetrieveCert(ctx context.Context, token, serialNumber string) (cert certs.Certificate, ca []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_cert for cert %s took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RetrieveCert(ctx, token, serialNumber)
}

func (lm *loggingMiddleware) RevokeCert(ctx context.Context, serialNumber string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method revoke_cert for cert %s and took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RevokeCert(ctx, serialNumber)
}

func (lm *loggingMiddleware) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (tokenString string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_cert_download_token for cert took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RetrieveCertDownloadToken(ctx, serialNumber)
}

func (lm *loggingMiddleware) RetrieveCAToken(ctx context.Context) (tokenString string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_cert_download_token for cert took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RetrieveCAToken(ctx)
}

func (lm *loggingMiddleware) IssueCert(ctx context.Context, entityID, ttl string, ipAddrs []string, options certs.SubjectOptions, privKey ...any) (cert certs.Certificate, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method issue_cert for took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.IssueCert(ctx, entityID, ttl, ipAddrs, options, privKey...)
}

func (lm *loggingMiddleware) ListCerts(ctx context.Context, pm certs.PageMetadata) (cp certs.CertificatePage, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_certs took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.ListCerts(ctx, pm)
}

func (lm *loggingMiddleware) RemoveCert(ctx context.Context, entityId string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remove_cert took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RemoveCert(ctx, entityId)
}

func (lm *loggingMiddleware) ViewCert(ctx context.Context, serialNumber string) (cert certs.Certificate, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_cert for serial number %s took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.ViewCert(ctx, serialNumber)
}

func (lm *loggingMiddleware) OCSP(ctx context.Context, serialNumber string) (cert *certs.Certificate, ocspStatus int, rootCACert *x509.Certificate, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method ocsp for serial number %s took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.OCSP(ctx, serialNumber)
}

func (lm *loggingMiddleware) GetEntityID(ctx context.Context, serialNumber string) (entityID string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_entity_id for serial number %s took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.GetEntityID(ctx, serialNumber)
}

func (lm *loggingMiddleware) GenerateCRL(ctx context.Context, caType certs.CertType) (crl []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method generate_crl took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.GenerateCRL(ctx, caType)
}

func (lm *loggingMiddleware) GetChainCA(ctx context.Context, token string) (cert certs.Certificate, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_chain_ca took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.GetChainCA(ctx, token)
}

func (lm *loggingMiddleware) IssueFromCSR(ctx context.Context, entityID, ttl string, csr certs.CSR) (c certs.Certificate, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method issue_from_csr took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.IssueFromCSR(ctx, entityID, ttl, csr)
}
