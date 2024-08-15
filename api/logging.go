// Copyright (c) Ultraviolet
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

func (lm *loggingMiddleware) RenewCert(ctx context.Context, token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method renew_cert for cert %s and token %s took %s to complete", id, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RenewCert(ctx, token, id)
}

func (lm *loggingMiddleware) RetrieveCert(ctx context.Context, token, id string) (cert certs.Certificate, ca []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_cert for cert %s and token %s took %s to complete", id, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RetrieveCert(ctx, token, id)
}

func (lm *loggingMiddleware) RevokeCert(ctx context.Context, token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method revoke_cert for cert %s and token %s took %s to complete", id, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RevokeCert(ctx, token, id)
}

func (lm *loggingMiddleware) RetrieveCertDownloadToken(ctx context.Context, token, id string) (tokenString string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_cert_download_token for cert %s and token %s took %s to complete", id, token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RetrieveCertDownloadToken(ctx, token, id)
}

func (lm *loggingMiddleware) IssueCert(ctx context.Context, token, entityID string, entityType certs.EntityType, ipAddrs []string) (id string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method issue_cert for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.IssueCert(ctx, token, entityID, entityType, ipAddrs)
}

func (lm *loggingMiddleware) ListCerts(ctx context.Context, token string, pm certs.PageMetadata) (cp certs.CertificatePage, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_certs took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.ListCerts(ctx, token, pm)
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
