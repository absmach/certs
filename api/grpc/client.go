// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"errors"
	"time"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

const svcName = "certs.ClientService"

var (
	errResponse = errors.New("invalid response type")
	errRequest  = errors.New("invalid request type")
)

type grpcClient struct {
	timeout               time.Duration
	getEntityID           endpoint.Endpoint
	revokeCerts           endpoint.Endpoint
	retrieveCert          endpoint.Endpoint
	retrieveDownloadToken endpoint.Endpoint
	issueCert             endpoint.Endpoint
	getCA                 endpoint.Endpoint
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

		revokeCerts: kitgrpc.NewClient(
			conn,
			svcName,
			"RevokeCerts",
			encodeRevokeCertsRequest,
			decodeRevokeCertsResponse,
			emptypb.Empty{},
		).Endpoint(),
		retrieveCert: kitgrpc.NewClient(
			conn,
			svcName,
			"RetrieveCert",
			encodeRetrieveCertRequest,
			decodeRetrieveCertResponse,
			certs.CertificateBundle{},
		).Endpoint(),

		retrieveDownloadToken: kitgrpc.NewClient(
			conn,
			svcName,
			"RetrieveCertDownloadToken",
			encodeRetrieveDownloadTokenRequest,
			decodeRetrieveDownloadTokenResponse,
			certs.RetrieveCertDownloadTokenRes{},
		).Endpoint(),
		issueCert: kitgrpc.NewClient(
			conn,
			svcName,
			"IssueCert",
			encodeIssueCertRequest,
			decodeIssueCertResponse,
			certs.IssueCertRes{},
		).Endpoint(),
		getCA: kitgrpc.NewClient(
			conn,
			svcName,
			"GetCA",
			encodeGetCARequest,
			decodeGetCAResponse,
			certs.Cert{},
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

func (c *grpcClient) RevokeCerts(ctx context.Context, req *certs.RevokeReq, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	res, err := c.revokeCerts(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.(*emptypb.Empty), nil
}

func (client *grpcClient) RetrieveCertDownloadToken(ctx context.Context, req *certs.RetrieveCertDownloadTokenReq, opts ...grpc.CallOption) (*certs.RetrieveCertDownloadTokenRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.retrieveDownloadToken(ctx, req)
	if err != nil {
		return nil, err
	}

	return &certs.RetrieveCertDownloadTokenRes{
		Token: res.(*certs.RetrieveCertDownloadTokenRes).Token,
	}, nil
}

func (client *grpcClient) RetrieveCert(ctx context.Context, req *certs.RetrieveCertReq, opts ...grpc.CallOption) (*certs.CertificateBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.retrieveCert(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.(*certs.CertificateBundle), nil
}

func (client *grpcClient) IssueCert(ctx context.Context, req *certs.IssueCertReq, opts ...grpc.CallOption) (*certs.IssueCertRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.issueCert(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.(*certs.IssueCertRes), nil
}

func (client *grpcClient) GetCA(ctx context.Context, req *certs.GetCAReq, opts ...grpc.CallOption) (*certs.Cert, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.getCA(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.(*certs.Cert), nil
}

func encodeGetEntityIDRequest(_ context.Context, request any) (any, error) {
	req := request.(*certs.EntityReq)
	return &certs.EntityReq{
		SerialNumber: req.GetSerialNumber(),
	}, nil
}

func decodeGetEntityIDResponse(_ context.Context, response any) (any, error) {
	res := response.(*certs.EntityRes)
	return &certs.EntityRes{
		EntityId: res.EntityId,
	}, nil
}

func encodeRevokeCertsRequest(_ context.Context, request any) (any, error) {
	req := request.(*certs.RevokeReq)
	return &certs.RevokeReq{
		EntityId: req.GetEntityId(),
	}, nil
}

func decodeRevokeCertsResponse(_ context.Context, response any) (any, error) {
	return &emptypb.Empty{}, nil
}

func encodeRetrieveCertRequest(ctx context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*certs.RetrieveCertReq)
	if !ok {
		return nil, errRequest
	}
	return req, nil
}

func encodeRetrieveDownloadTokenRequest(ctx context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*certs.RetrieveCertDownloadTokenReq)
	if !ok {
		return nil, errRequest
	}
	return req, nil
}

func encodeIssueCertRequest(ctx context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*certs.IssueCertReq)
	if !ok {
		return nil, errRequest
	}
	return req, nil
}

func encodeGetCARequest(ctx context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*certs.GetCAReq)
	if !ok {
		return nil, errRequest
	}
	return req, nil
}

func decodeRetrieveCertResponse(ctx context.Context, response interface{}) (interface{}, error) {
	res, ok := response.(*certs.CertificateBundle)
	if !ok {
		return nil, errResponse
	}
	return res, nil
}

func decodeRetrieveDownloadTokenResponse(ctx context.Context, response interface{}) (interface{}, error) {
	res, ok := response.(*certs.RetrieveCertDownloadTokenRes)
	if !ok {
		return nil, errResponse
	}
	return res, nil
}

func decodeIssueCertResponse(ctx context.Context, response interface{}) (interface{}, error) {
	res, ok := response.(*certs.IssueCertRes)
	if !ok {
		return nil, errResponse
	}
	return res, nil
}

func decodeGetCAResponse(ctx context.Context, response interface{}) (interface{}, error) {
	res, ok := response.(*certs.Cert)
	if !ok {
		return nil, errResponse
	}
	return res, nil
}
