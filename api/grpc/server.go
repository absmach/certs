// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	"github.com/absmach/certs"
	"github.com/absmach/certs/api/http"
	"github.com/absmach/certs/errors"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ certs.CertsServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	getEntity             kitgrpc.Handler
	revokeCerts           kitgrpc.Handler
	retrieveCert          kitgrpc.Handler
	retrieveDownloadToken kitgrpc.Handler
	issueCert             kitgrpc.Handler
	getCA                 kitgrpc.Handler
	certs.UnimplementedCertsServiceServer
}

func NewServer(svc certs.Service) certs.CertsServiceServer {
	return &grpcServer{
		getEntity: kitgrpc.NewServer(
			(getEntityEndpoint(svc)),
			decodeGetEntityReq,
			encodeGetEntityRes,
		),
		revokeCerts: kitgrpc.NewServer(
			(revokeCertsEndpoint(svc)),
			decodeRevokeCertsReq,
			encodeRevokeCertsRes,
		),
		retrieveCert: kitgrpc.NewServer(
			(retrieveCert(svc)),
			decodeRetrieveCertReq,
			encodeRetrieveCertRes,
		),
		retrieveDownloadToken: kitgrpc.NewServer(
			(retrieveDownloadToken(svc)),
			decodeRetrieveDownloadTokenReq,
			encodeRetrieveDownloadTokenRes,
		),
		issueCert: kitgrpc.NewServer(
			(issueEndpoint(svc)),
			decodeIssueCertReq,
			encodeIssueCertRes,
		),
		getCA: kitgrpc.NewServer(
			(getCAEndpoint(svc)),
			decodeGetCAReq,
			encodeGetCARes,
		),
	}
}

func decodeGetEntityReq(_ context.Context, req any) (any, error) {
	return req.(*certs.EntityReq), nil
}

func encodeGetEntityRes(_ context.Context, res any) (any, error) {
	return res.(*certs.EntityRes), nil
}

func decodeRevokeCertsReq(_ context.Context, req any) (any, error) {
	return req.(*certs.RevokeReq), nil
}

func encodeRevokeCertsRes(_ context.Context, res any) (any, error) {
	return res.(*emptypb.Empty), nil
}

func decodeRetrieveCertReq(_ context.Context, req interface{}) (interface{}, error) {
	return req.(*certs.RetrieveCertReq), nil
}

func encodeRetrieveCertRes(_ context.Context, res interface{}) (interface{}, error) {
	return res.(*certs.CertificateBundle), nil
}

func decodeRetrieveDownloadTokenReq(_ context.Context, req interface{}) (interface{}, error) {
	return req.(*certs.RetrieveCertDownloadTokenReq), nil
}

func encodeRetrieveDownloadTokenRes(_ context.Context, res interface{}) (interface{}, error) {
	return res.(*certs.RetrieveCertDownloadTokenRes), nil
}

func decodeIssueCertReq(_ context.Context, req interface{}) (interface{}, error) {
	return req.(*certs.IssueCertReq), nil
}

func encodeIssueCertRes(_ context.Context, res interface{}) (interface{}, error) {
	return res.(*certs.IssueCertRes), nil
}

func decodeGetCAReq(_ context.Context, req interface{}) (interface{}, error) {
	return req.(*certs.GetCAReq), nil
}

func encodeGetCARes(_ context.Context, res interface{}) (interface{}, error) {
	return res.(*certs.Cert), nil
}

// GetEntityID returns the entity ID for the given entity request.
func (g *grpcServer) GetEntityID(ctx context.Context, req *certs.EntityReq) (*certs.EntityRes, error) {
	_, res, err := g.getEntity.ServeGRPC(ctx, req)
	if err != nil {
		return &certs.EntityRes{}, encodeError(err)
	}
	return res.(*certs.EntityRes), nil
}

func (g *grpcServer) RevokeCerts(ctx context.Context, req *certs.RevokeReq) (*emptypb.Empty, error) {
	_, res, err := g.revokeCerts.ServeGRPC(ctx, req)
	if err != nil {
		return &emptypb.Empty{}, encodeError(err)
	}
	return res.(*emptypb.Empty), nil
}

func (g *grpcServer) RetrieveCert(ctx context.Context, req *certs.RetrieveCertReq) (*certs.CertificateBundle, error) {
	_, res, err := g.retrieveCert.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*certs.CertificateBundle), nil
}

func (g *grpcServer) RetrieveCertDownloadToken(ctx context.Context, req *certs.RetrieveCertDownloadTokenReq) (*certs.RetrieveCertDownloadTokenRes, error) {
	_, res, err := g.retrieveDownloadToken.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*certs.RetrieveCertDownloadTokenRes), nil
}

func (g *grpcServer) IssueCert(ctx context.Context, req *certs.IssueCertReq) (*certs.IssueCertRes, error) {
	_, res, err := g.issueCert.ServeGRPC(ctx, req)
	if err != nil {
		return &certs.IssueCertRes{}, encodeError(err)
	}
	return res.(*certs.IssueCertRes), nil
}

func (g *grpcServer) GetCA(ctx context.Context, req *certs.GetCAReq) (*certs.Cert, error) {
	_, res, err := g.getCA.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*certs.Cert), nil
}

func encodeError(err error) error {
	switch {
	case errors.Contains(err, nil):
		return nil
	case errors.Contains(err, certs.ErrMalformedEntity),
		errors.Contains(err, http.ErrMissingEntityID):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Contains(err, certs.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Contains(err, certs.ErrConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Contains(err, certs.ErrCreateEntity),
		errors.Contains(err, certs.ErrUpdateEntity),
		errors.Contains(err, certs.ErrViewEntity),
		errors.Contains(err, certs.ErrGetToken):
		return status.Error(codes.Internal, err.Error())
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}
