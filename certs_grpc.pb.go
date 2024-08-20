// Copyright (c) Abstract Machines

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             v5.27.1
// source: certs.proto

package certs

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	CertsService_GetEntityID_FullMethodName = "/absmach.certs.CertsService/GetEntityID"
)

// CertsServiceClient is the client API for CertsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CertsServiceClient interface {
	GetEntityID(ctx context.Context, in *EntityReq, opts ...grpc.CallOption) (*EntityRes, error)
}

type certsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCertsServiceClient(cc grpc.ClientConnInterface) CertsServiceClient {
	return &certsServiceClient{cc}
}

func (c *certsServiceClient) GetEntityID(ctx context.Context, in *EntityReq, opts ...grpc.CallOption) (*EntityRes, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(EntityRes)
	err := c.cc.Invoke(ctx, CertsService_GetEntityID_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CertsServiceServer is the server API for CertsService service.
// All implementations must embed UnimplementedCertsServiceServer
// for forward compatibility
type CertsServiceServer interface {
	GetEntityID(context.Context, *EntityReq) (*EntityRes, error)
	mustEmbedUnimplementedCertsServiceServer()
}

// UnimplementedCertsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCertsServiceServer struct {
}

func (UnimplementedCertsServiceServer) GetEntityID(context.Context, *EntityReq) (*EntityRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEntityID not implemented")
}
func (UnimplementedCertsServiceServer) mustEmbedUnimplementedCertsServiceServer() {}

// UnsafeCertsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CertsServiceServer will
// result in compilation errors.
type UnsafeCertsServiceServer interface {
	mustEmbedUnimplementedCertsServiceServer()
}

func RegisterCertsServiceServer(s grpc.ServiceRegistrar, srv CertsServiceServer) {
	s.RegisterService(&CertsService_ServiceDesc, srv)
}

func _CertsService_GetEntityID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EntityReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertsServiceServer).GetEntityID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CertsService_GetEntityID_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertsServiceServer).GetEntityID(ctx, req.(*EntityReq))
	}
	return interceptor(ctx, in, info, handler)
}

// CertsService_ServiceDesc is the grpc.ServiceDesc for CertsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CertsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "absmach.certs.CertsService",
	HandlerType: (*CertsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetEntityID",
			Handler:    _CertsService_GetEntityID_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "certs.proto",
}