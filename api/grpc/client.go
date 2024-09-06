// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"time"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc"
)

const svcName = "certs.ClientService"

type grpcClient struct {
	timeout     time.Duration
	getEntityID endpoint.Endpoint
}

func NewClient(conn *grpc.ClientConn, timeout time.Duration) certs.CertsServiceClient {
	return &grpcClient{
		getEntityID: kitgrpc.NewClient(
			conn,
			svcName,
			"GetEntityID",
			encodeGetEntityIDRequest,
			decodeGetEntityIDResponse,
			certs.EntityRes{},
		).Endpoint(),

		timeout: timeout,
	}
}

func (c *grpcClient) GetEntityID(ctx context.Context, req *certs.EntityReq, _ ...grpc.CallOption) (*certs.EntityRes, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	res, err := c.getEntityID(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.(*certs.EntityRes), nil
}

func encodeGetEntityIDRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(*certs.EntityReq)
	return &certs.EntityReq{
		SerialNumber: req.GetSerialNumber(),
	}, nil
}

func decodeGetEntityIDResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(*certs.EntityRes)
	return &certs.EntityRes{
		EntityId: res.EntityId,
	}, nil
}
