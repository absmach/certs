// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/endpoint"
)

func getEntityEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*certs.EntityReq)

		entityID, err := svc.GetEntityID(ctx, req.SerialNumber)
		if err != nil {
			return nil, err
		}

		return &certs.EntityRes{EntityId: entityID}, nil
	}
}
