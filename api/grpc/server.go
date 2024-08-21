// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	"github.com/absmach/certs"
	"github.com/absmach/certs/pkg/apiutil"
	"github.com/absmach/certs/pkg/errors"
	"github.com/absmach/certs/pkg/errors/service"
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
	case errors.Contains(err, service.ErrMalformedEntity),
		errors.Contains(err, apiutil.ErrMissingID),
		errors.Contains(err, apiutil.ErrEmptyList),
		errors.Contains(err, apiutil.ErrNameSize),
		errors.Contains(err, apiutil.ErrMalformedPolicy),
		errors.Contains(err, apiutil.ErrMissingUser),
		errors.Contains(err, apiutil.ErrMissingComputation),
		errors.Contains(err, apiutil.ErrInvalidRole):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Contains(err, service.ErrAuthentication):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Contains(err, service.ErrAuthorization):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Contains(err, service.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Contains(err, service.ErrConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Contains(err, apiutil.ErrUnsupportedContentType):
		return status.Error(codes.Unimplemented, err.Error())
	case errors.Contains(err, service.ErrCreateEntity),
		errors.Contains(err, service.ErrUpdateEntity),
		errors.Contains(err, service.ErrViewEntity),
		errors.Contains(err, service.ErrRemoveEntity):
		return status.Error(codes.Internal, err.Error())
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}
