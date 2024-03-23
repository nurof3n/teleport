// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: teleport/clusterconfig/v1/clusterconfig_service.proto

package clusterconfigv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ClusterConfigService_GetClusterAccessGraphConfig_FullMethodName = "/teleport.clusterconfig.v1.ClusterConfigService/GetClusterAccessGraphConfig"
)

// ClusterConfigServiceClient is the client API for ClusterConfigService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ClusterConfigServiceClient interface {
	// GetClusterAccessGraphConfig retrieves the Cluster Access Graph configuration from Auth server.
	GetClusterAccessGraphConfig(ctx context.Context, in *GetClusterAccessGraphConfigRequest, opts ...grpc.CallOption) (*GetClusterAccessGraphConfigResponse, error)
}

type clusterConfigServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewClusterConfigServiceClient(cc grpc.ClientConnInterface) ClusterConfigServiceClient {
	return &clusterConfigServiceClient{cc}
}

func (c *clusterConfigServiceClient) GetClusterAccessGraphConfig(ctx context.Context, in *GetClusterAccessGraphConfigRequest, opts ...grpc.CallOption) (*GetClusterAccessGraphConfigResponse, error) {
	out := new(GetClusterAccessGraphConfigResponse)
	err := c.cc.Invoke(ctx, ClusterConfigService_GetClusterAccessGraphConfig_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClusterConfigServiceServer is the server API for ClusterConfigService service.
// All implementations must embed UnimplementedClusterConfigServiceServer
// for forward compatibility
type ClusterConfigServiceServer interface {
	// GetClusterAccessGraphConfig retrieves the Cluster Access Graph configuration from Auth server.
	GetClusterAccessGraphConfig(context.Context, *GetClusterAccessGraphConfigRequest) (*GetClusterAccessGraphConfigResponse, error)
	mustEmbedUnimplementedClusterConfigServiceServer()
}

// UnimplementedClusterConfigServiceServer must be embedded to have forward compatible implementations.
type UnimplementedClusterConfigServiceServer struct {
}

func (UnimplementedClusterConfigServiceServer) GetClusterAccessGraphConfig(context.Context, *GetClusterAccessGraphConfigRequest) (*GetClusterAccessGraphConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetClusterAccessGraphConfig not implemented")
}
func (UnimplementedClusterConfigServiceServer) mustEmbedUnimplementedClusterConfigServiceServer() {}

// UnsafeClusterConfigServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ClusterConfigServiceServer will
// result in compilation errors.
type UnsafeClusterConfigServiceServer interface {
	mustEmbedUnimplementedClusterConfigServiceServer()
}

func RegisterClusterConfigServiceServer(s grpc.ServiceRegistrar, srv ClusterConfigServiceServer) {
	s.RegisterService(&ClusterConfigService_ServiceDesc, srv)
}

func _ClusterConfigService_GetClusterAccessGraphConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetClusterAccessGraphConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterConfigServiceServer).GetClusterAccessGraphConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ClusterConfigService_GetClusterAccessGraphConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterConfigServiceServer).GetClusterAccessGraphConfig(ctx, req.(*GetClusterAccessGraphConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ClusterConfigService_ServiceDesc is the grpc.ServiceDesc for ClusterConfigService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ClusterConfigService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.clusterconfig.v1.ClusterConfigService",
	HandlerType: (*ClusterConfigServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetClusterAccessGraphConfig",
			Handler:    _ClusterConfigService_GetClusterAccessGraphConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/clusterconfig/v1/clusterconfig_service.proto",
}