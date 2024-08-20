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

func (lm *loggingMiddleware) RenewCert(ctx context.Context, userId, serialNumber string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method renew_cert for cert %s and user %s took %s to complete", serialNumber, userId, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RenewCert(ctx, userId, serialNumber)
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

func (lm *loggingMiddleware) RevokeCert(ctx context.Context, userId, serialNumber string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method revoke_cert for cert %s and user %s took %s to complete", serialNumber, userId, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RevokeCert(ctx, userId, serialNumber)
}

func (lm *loggingMiddleware) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (tokenString string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_cert_download_token for cert %s took %s to complete", serialNumber, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.RetrieveCertDownloadToken(ctx, serialNumber)
}

func (lm *loggingMiddleware) IssueCert(ctx context.Context, userId, entityID string, entityType certs.EntityType, ipAddrs []string) (serialNumber string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method issue_cert for user %s took %s to complete", userId, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.IssueCert(ctx, userId, entityID, entityType, ipAddrs)
}

func (lm *loggingMiddleware) ListCerts(ctx context.Context, userId string, pm certs.PageMetadata) (cp certs.CertificatePage, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_certs with user %s took %s to complete", userId, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.ListCerts(ctx, userId, pm)
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
