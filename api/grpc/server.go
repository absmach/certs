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
)

var _ certs.CertsServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	getEntity kitgrpc.Handler
	certs.UnimplementedCertsServiceServer
}

func NewServer(svc certs.Service) certs.CertsServiceServer {
	return &grpcServer{
		getEntity: kitgrpc.NewServer(
			(getEntityEndpoint(svc)),
			decodeGetEntityReq,
			encodeGetEntityRes,
		),
	}
}

func decodeGetEntityReq(_ context.Context, req interface{}) (interface{}, error) {
	return req.(*certs.EntityReq), nil
}

func encodeGetEntityRes(_ context.Context, res interface{}) (interface{}, error) {
	return res.(*certs.EntityRes), nil
}

// GetEntityID returns the entity ID for the given entity request.
func (g *grpcServer) GetEntityID(ctx context.Context, req *certs.EntityReq) (*certs.EntityRes, error) {
	_, res, err := g.getEntity.ServeGRPC(context.Background(), req)
	if err != nil {
		return &certs.EntityRes{}, encodeError(err)
	}
	return res.(*certs.EntityRes), nil
}

func encodeError(err error) error {
	switch {
	case errors.Contains(err, nil):
		return nil
	case errors.Contains(err, certs.ErrMalformedEntity),
		errors.Contains(err, http.ErrMissingID):
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
