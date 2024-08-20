// Copyright (c) Abstract Machines

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: certs.proto

package certs

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EntityReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SerialNumber string `protobuf:"bytes,1,opt,name=serial_number,json=serialNumber,proto3" json:"serial_number,omitempty"`
}

func (x *EntityReq) Reset() {
	*x = EntityReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_certs_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EntityReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EntityReq) ProtoMessage() {}

func (x *EntityReq) ProtoReflect() protoreflect.Message {
	mi := &file_certs_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EntityReq.ProtoReflect.Descriptor instead.
func (*EntityReq) Descriptor() ([]byte, []int) {
	return file_certs_proto_rawDescGZIP(), []int{0}
}

func (x *EntityReq) GetSerialNumber() string {
	if x != nil {
		return x.SerialNumber
	}
	return ""
}

type EntityRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EntityId string `protobuf:"bytes,1,opt,name=entity_id,json=entityId,proto3" json:"entity_id,omitempty"`
}

func (x *EntityRes) Reset() {
	*x = EntityRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_certs_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EntityRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EntityRes) ProtoMessage() {}

func (x *EntityRes) ProtoReflect() protoreflect.Message {
	mi := &file_certs_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EntityRes.ProtoReflect.Descriptor instead.
func (*EntityRes) Descriptor() ([]byte, []int) {
	return file_certs_proto_rawDescGZIP(), []int{1}
}

func (x *EntityRes) GetEntityId() string {
	if x != nil {
		return x.EntityId
	}
	return ""
}

var File_certs_proto protoreflect.FileDescriptor

var file_certs_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x61,
	0x62, 0x73, 0x6d, 0x61, 0x63, 0x68, 0x2e, 0x63, 0x65, 0x72, 0x74, 0x73, 0x22, 0x30, 0x0a, 0x09,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x65, 0x72,
	0x69, 0x61, 0x6c, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0c, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x22, 0x28,
	0x0a, 0x09, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x32, 0x53, 0x0a, 0x0c, 0x43, 0x65, 0x72, 0x74,
	0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x43, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x45,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x44, 0x12, 0x18, 0x2e, 0x61, 0x62, 0x73, 0x6d, 0x61, 0x63,
	0x68, 0x2e, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2e, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65,
	0x71, 0x1a, 0x18, 0x2e, 0x61, 0x62, 0x73, 0x6d, 0x61, 0x63, 0x68, 0x2e, 0x63, 0x65, 0x72, 0x74,
	0x73, 0x2e, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x22, 0x00, 0x42, 0x09, 0x5a,
	0x07, 0x2e, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_certs_proto_rawDescOnce sync.Once
	file_certs_proto_rawDescData = file_certs_proto_rawDesc
)

func file_certs_proto_rawDescGZIP() []byte {
	file_certs_proto_rawDescOnce.Do(func() {
		file_certs_proto_rawDescData = protoimpl.X.CompressGZIP(file_certs_proto_rawDescData)
	})
	return file_certs_proto_rawDescData
}

var file_certs_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_certs_proto_goTypes = []any{
	(*EntityReq)(nil), // 0: absmach.certs.entityReq
	(*EntityRes)(nil), // 1: absmach.certs.entityRes
}
var file_certs_proto_depIdxs = []int32{
	0, // 0: absmach.certs.CertsService.GetEntityID:input_type -> absmach.certs.entityReq
	1, // 1: absmach.certs.CertsService.GetEntityID:output_type -> absmach.certs.entityRes
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_certs_proto_init() }
func file_certs_proto_init() {
	if File_certs_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_certs_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*EntityReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_certs_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*EntityRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_certs_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_certs_proto_goTypes,
		DependencyIndexes: file_certs_proto_depIdxs,
		MessageInfos:      file_certs_proto_msgTypes,
	}.Build()
	File_certs_proto = out.File
	file_certs_proto_rawDesc = nil
	file_certs_proto_goTypes = nil
	file_certs_proto_depIdxs = nil
}