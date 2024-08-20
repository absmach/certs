// Copyright (c) Ultraviolet
package http

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"strings"
	"time"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/endpoint"
	"golang.org/x/crypto/ocsp"
)

func renewCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return renewCertRes{}, err
		}

		if err = svc.RenewCert(ctx, req.userId, req.id); err != nil {
			return renewCertRes{}, err
		}

		return renewCertRes{renewed: true}, nil
	}
}

func revokeCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return revokeCertRes{}, err
		}

		if err = svc.RevokeCert(ctx, req.userId, req.id); err != nil {
			return revokeCertRes{}, err
		}

		return revokeCertRes{revoked: true}, nil
	}
}

func requestCertDownloadTokenEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return requestCertDownloadTokenRes{}, err
		}

		token, err := svc.RetrieveCertDownloadToken(ctx, req.id)
		if err != nil {
			return requestCertDownloadTokenRes{}, err
		}

		return requestCertDownloadTokenRes{Token: token}, nil
	}
}

func downloadCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return downloadCertRes{}, err
		}

		cert, ca, err := svc.RetrieveCert(ctx, req.id)
		if err != nil {
			return downloadCertRes{}, err
		}

		return downloadCertRes{Certificate: cert.Certificate, PrivateKey: cert.Key, CA: ca}, nil
	}
}

func issueCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(issueCertReq)
		if err := req.validate(); err != nil {
			return issueCertRes{}, err
		}

		serialNumber, err := svc.IssueCert(ctx, req.userId, req.entityID, certs.EntityType(req.entityType), req.IpAddrs)
		if err != nil {
			return issueCertRes{}, err
		}

		return issueCertRes{issued: true, SerialNumber: serialNumber}, nil
	}
}

func listCertsEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listCertsReq)
		if err := req.validate(); err != nil {
			return listCertsRes{}, err
		}

		certPage, err := svc.ListCerts(ctx, req.userId, req.pm)
		if err != nil {
			return listCertsRes{}, err
		}

		return listCertsRes{CertificatePage: certPage}, nil
	}
}

func ocspEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ocspReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cert, status, issuerCert, err := svc.OCSP(ctx, req.req.SerialNumber.String())
		if err != nil {
			return nil, err
		}

		switch strings.ToUpper(req.statusParam) {
		case "REVOKE":
			status = ocsp.Revoked
		case "GOOD":
			status = ocsp.Good
		case "SERVERFAILED":
			status = ocsp.ServerFailed
		case "RANDOM":
			r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
			status = r.Intn(ocsp.ServerFailed)
		}

		template := ocsp.Response{
			Status:       status,
			SerialNumber: req.req.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now(),
			IssuerHash:   req.req.HashAlgorithm,
		}
		if template.Status == ocsp.Revoked {
			template.RevokedAt = time.Now()
		}
		var signer crypto.Signer

		if cert != nil {
			if cert.Revoked {
				template.RevokedAt = cert.ExpiryDate
				template.RevocationReason = ocsp.Unspecified
			}
			pemBlock, _ := pem.Decode(cert.Certificate)
			parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, err
			}
			template.Certificate = parsedCert
			keyBlock, _ := pem.Decode(cert.Key)
			privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, err
			}
			signer = privKey
			if !parsedCert.NotAfter.After(time.Now()) {
				template.Status = ocsp.Revoked
				template.RevocationReason = ocsp.CessationOfOperation
			}
		}

		return ocspRes{
			template:   template,
			issuerCert: issuerCert,
			signer:     signer,
		}, nil
	}
}