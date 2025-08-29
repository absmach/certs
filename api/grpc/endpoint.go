// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/endpoint"
	"google.golang.org/protobuf/types/known/emptypb"
)

func getEntityEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(*certs.EntityReq)

		entityID, err := svc.GetEntityID(ctx, req.SerialNumber)
		if err != nil {
			return nil, err
		}

		return &certs.EntityRes{EntityId: entityID}, nil
	}
}

func revokeCertsEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request any) (any, error) {
		req := request.(*certs.RevokeReq)

		err := svc.RevokeAll(ctx, req.EntityId)
		if err != nil {
			return nil, err
		}

		return &emptypb.Empty{}, nil
	}
}

func retrieveCert(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*certs.RetrieveCertReq)
		crt, ca, err := svc.RetrieveCert(ctx, req.DownloadToken, req.SerialNumber)
		if err != nil {
			return nil, err
		}
		return &certs.CertificateBundle{
			Ca:          ca,
			Certificate: crt.Certificate,
			PrivateKey:  crt.Key,
		}, nil
	}
}

func retrieveDownloadToken(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*certs.RetrieveCertDownloadTokenReq)
		downloadToken, err := svc.RetrieveCertDownloadToken(ctx, req.SerialNumber)
		if err != nil {
			return &certs.RetrieveCertDownloadTokenRes{}, err
		}
		return &certs.RetrieveCertDownloadTokenRes{
			Token: downloadToken,
		}, nil
	}
}

func issueEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*certs.IssueCertReq)

		var subjectOptions certs.SubjectOptions
		if req.SubjectOptions != nil {
			subjectOptions = certs.SubjectOptions{
				CommonName:         req.SubjectOptions.CommonName,
				Organization:       req.SubjectOptions.Organization,
				Country:            req.SubjectOptions.Country,
				OrganizationalUnit: req.SubjectOptions.OrganizationalUnit,
				Province:           req.SubjectOptions.Province,
				Locality:           req.SubjectOptions.Locality,
				StreetAddress:      req.SubjectOptions.StreetAddress,
				PostalCode:         req.SubjectOptions.PostalCode,
				DnsNames:           req.SubjectOptions.DnsNames,
			}
		}
		
		crt, err := svc.IssueCert(ctx, req.EntityId, req.EntityType, req.Ttl, req.IpAddresses, subjectOptions)
		if err != nil {
			return &certs.IssueCertRes{}, err
		}
		return &certs.IssueCertRes{
			SerialNumber: crt.SerialNumber,
		}, nil
	}
}

func getCAEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		ca, err := svc.GetCA(ctx)
		if err != nil {
			return &certs.Cert{}, err
		}
		return &certs.Cert{
			SerialNumber: ca.SerialNumber,
			Certificate:  string(ca.Certificate),
			DownloadUrl:  ca.DownloadUrl,
			EntityId:     ca.EntityID,
			Key:          string(ca.Key),
		}, nil
	}
}
