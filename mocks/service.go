// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	context "context"

	certs "github.com/absmach/certs"

	mock "github.com/stretchr/testify/mock"

	rsa "crypto/rsa"

	x509 "crypto/x509"
)

// MockService is an autogenerated mock type for the Service type
type MockService struct {
	mock.Mock
}

type MockService_Expecter struct {
	mock *mock.Mock
}

func (_m *MockService) EXPECT() *MockService_Expecter {
	return &MockService_Expecter{mock: &_m.Mock}
}

// CreateCSR provides a mock function with given fields: ctx, metadata, privKey
func (_m *MockService) CreateCSR(ctx context.Context, metadata certs.CSRMetadata, privKey interface{}) (certs.CSR, error) {
	ret := _m.Called(ctx, metadata, privKey)

	if len(ret) == 0 {
		panic("no return value specified for CreateCSR")
	}

	var r0 certs.CSR
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, certs.CSRMetadata, interface{}) (certs.CSR, error)); ok {
		return rf(ctx, metadata, privKey)
	}
	if rf, ok := ret.Get(0).(func(context.Context, certs.CSRMetadata, interface{}) certs.CSR); ok {
		r0 = rf(ctx, metadata, privKey)
	} else {
		r0 = ret.Get(0).(certs.CSR)
	}

	if rf, ok := ret.Get(1).(func(context.Context, certs.CSRMetadata, interface{}) error); ok {
		r1 = rf(ctx, metadata, privKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_CreateCSR_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateCSR'
type MockService_CreateCSR_Call struct {
	*mock.Call
}

// CreateCSR is a helper method to define mock.On call
//   - ctx context.Context
//   - metadata certs.CSRMetadata
//   - privKey interface{}
func (_e *MockService_Expecter) CreateCSR(ctx interface{}, metadata interface{}, privKey interface{}) *MockService_CreateCSR_Call {
	return &MockService_CreateCSR_Call{Call: _e.mock.On("CreateCSR", ctx, metadata, privKey)}
}

func (_c *MockService_CreateCSR_Call) Run(run func(ctx context.Context, metadata certs.CSRMetadata, privKey interface{})) *MockService_CreateCSR_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(certs.CSRMetadata), args[2].(interface{}))
	})
	return _c
}

func (_c *MockService_CreateCSR_Call) Return(_a0 certs.CSR, _a1 error) *MockService_CreateCSR_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_CreateCSR_Call) RunAndReturn(run func(context.Context, certs.CSRMetadata, interface{}) (certs.CSR, error)) *MockService_CreateCSR_Call {
	_c.Call.Return(run)
	return _c
}

// GenerateCRL provides a mock function with given fields: ctx, caType
func (_m *MockService) GenerateCRL(ctx context.Context, caType certs.CertType) ([]byte, error) {
	ret := _m.Called(ctx, caType)

	if len(ret) == 0 {
		panic("no return value specified for GenerateCRL")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, certs.CertType) ([]byte, error)); ok {
		return rf(ctx, caType)
	}
	if rf, ok := ret.Get(0).(func(context.Context, certs.CertType) []byte); ok {
		r0 = rf(ctx, caType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, certs.CertType) error); ok {
		r1 = rf(ctx, caType)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_GenerateCRL_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GenerateCRL'
type MockService_GenerateCRL_Call struct {
	*mock.Call
}

// GenerateCRL is a helper method to define mock.On call
//   - ctx context.Context
//   - caType certs.CertType
func (_e *MockService_Expecter) GenerateCRL(ctx interface{}, caType interface{}) *MockService_GenerateCRL_Call {
	return &MockService_GenerateCRL_Call{Call: _e.mock.On("GenerateCRL", ctx, caType)}
}

func (_c *MockService_GenerateCRL_Call) Run(run func(ctx context.Context, caType certs.CertType)) *MockService_GenerateCRL_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(certs.CertType))
	})
	return _c
}

func (_c *MockService_GenerateCRL_Call) Return(_a0 []byte, _a1 error) *MockService_GenerateCRL_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_GenerateCRL_Call) RunAndReturn(run func(context.Context, certs.CertType) ([]byte, error)) *MockService_GenerateCRL_Call {
	_c.Call.Return(run)
	return _c
}

// GetChainCA provides a mock function with given fields: ctx, token
func (_m *MockService) GetChainCA(ctx context.Context, token string) (certs.Certificate, error) {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for GetChainCA")
	}

	var r0 certs.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (certs.Certificate, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) certs.Certificate); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Get(0).(certs.Certificate)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_GetChainCA_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetChainCA'
type MockService_GetChainCA_Call struct {
	*mock.Call
}

// GetChainCA is a helper method to define mock.On call
//   - ctx context.Context
//   - token string
func (_e *MockService_Expecter) GetChainCA(ctx interface{}, token interface{}) *MockService_GetChainCA_Call {
	return &MockService_GetChainCA_Call{Call: _e.mock.On("GetChainCA", ctx, token)}
}

func (_c *MockService_GetChainCA_Call) Run(run func(ctx context.Context, token string)) *MockService_GetChainCA_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_GetChainCA_Call) Return(_a0 certs.Certificate, _a1 error) *MockService_GetChainCA_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_GetChainCA_Call) RunAndReturn(run func(context.Context, string) (certs.Certificate, error)) *MockService_GetChainCA_Call {
	_c.Call.Return(run)
	return _c
}

// GetEntityID provides a mock function with given fields: ctx, serialNumber
func (_m *MockService) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for GetEntityID")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_GetEntityID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetEntityID'
type MockService_GetEntityID_Call struct {
	*mock.Call
}

// GetEntityID is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockService_Expecter) GetEntityID(ctx interface{}, serialNumber interface{}) *MockService_GetEntityID_Call {
	return &MockService_GetEntityID_Call{Call: _e.mock.On("GetEntityID", ctx, serialNumber)}
}

func (_c *MockService_GetEntityID_Call) Run(run func(ctx context.Context, serialNumber string)) *MockService_GetEntityID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_GetEntityID_Call) Return(_a0 string, _a1 error) *MockService_GetEntityID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_GetEntityID_Call) RunAndReturn(run func(context.Context, string) (string, error)) *MockService_GetEntityID_Call {
	_c.Call.Return(run)
	return _c
}

// IssueCert provides a mock function with given fields: ctx, entityID, ttl, ipAddrs, option, privKey
func (_m *MockService) IssueCert(ctx context.Context, entityID string, ttl string, ipAddrs []string, option certs.SubjectOptions, privKey ...*rsa.PrivateKey) (certs.Certificate, error) {
	_va := make([]interface{}, len(privKey))
	for _i := range privKey {
		_va[_i] = privKey[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, entityID, ttl, ipAddrs, option)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for IssueCert")
	}

	var r0 certs.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []string, certs.SubjectOptions, ...*rsa.PrivateKey) (certs.Certificate, error)); ok {
		return rf(ctx, entityID, ttl, ipAddrs, option, privKey...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []string, certs.SubjectOptions, ...*rsa.PrivateKey) certs.Certificate); ok {
		r0 = rf(ctx, entityID, ttl, ipAddrs, option, privKey...)
	} else {
		r0 = ret.Get(0).(certs.Certificate)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, []string, certs.SubjectOptions, ...*rsa.PrivateKey) error); ok {
		r1 = rf(ctx, entityID, ttl, ipAddrs, option, privKey...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_IssueCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IssueCert'
type MockService_IssueCert_Call struct {
	*mock.Call
}

// IssueCert is a helper method to define mock.On call
//   - ctx context.Context
//   - entityID string
//   - ttl string
//   - ipAddrs []string
//   - option certs.SubjectOptions
//   - privKey ...*rsa.PrivateKey
func (_e *MockService_Expecter) IssueCert(ctx interface{}, entityID interface{}, ttl interface{}, ipAddrs interface{}, option interface{}, privKey ...interface{}) *MockService_IssueCert_Call {
	return &MockService_IssueCert_Call{Call: _e.mock.On("IssueCert",
		append([]interface{}{ctx, entityID, ttl, ipAddrs, option}, privKey...)...)}
}

func (_c *MockService_IssueCert_Call) Run(run func(ctx context.Context, entityID string, ttl string, ipAddrs []string, option certs.SubjectOptions, privKey ...*rsa.PrivateKey)) *MockService_IssueCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]*rsa.PrivateKey, len(args)-5)
		for i, a := range args[5:] {
			if a != nil {
				variadicArgs[i] = a.(*rsa.PrivateKey)
			}
		}
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].([]string), args[4].(certs.SubjectOptions), variadicArgs...)
	})
	return _c
}

func (_c *MockService_IssueCert_Call) Return(_a0 certs.Certificate, _a1 error) *MockService_IssueCert_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_IssueCert_Call) RunAndReturn(run func(context.Context, string, string, []string, certs.SubjectOptions, ...*rsa.PrivateKey) (certs.Certificate, error)) *MockService_IssueCert_Call {
	_c.Call.Return(run)
	return _c
}

// ListCerts provides a mock function with given fields: ctx, pm
func (_m *MockService) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListCerts")
	}

	var r0 certs.CertificatePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, certs.PageMetadata) (certs.CertificatePage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, certs.PageMetadata) certs.CertificatePage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(certs.CertificatePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, certs.PageMetadata) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_ListCerts_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListCerts'
type MockService_ListCerts_Call struct {
	*mock.Call
}

// ListCerts is a helper method to define mock.On call
//   - ctx context.Context
//   - pm certs.PageMetadata
func (_e *MockService_Expecter) ListCerts(ctx interface{}, pm interface{}) *MockService_ListCerts_Call {
	return &MockService_ListCerts_Call{Call: _e.mock.On("ListCerts", ctx, pm)}
}

func (_c *MockService_ListCerts_Call) Run(run func(ctx context.Context, pm certs.PageMetadata)) *MockService_ListCerts_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(certs.PageMetadata))
	})
	return _c
}

func (_c *MockService_ListCerts_Call) Return(_a0 certs.CertificatePage, _a1 error) *MockService_ListCerts_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_ListCerts_Call) RunAndReturn(run func(context.Context, certs.PageMetadata) (certs.CertificatePage, error)) *MockService_ListCerts_Call {
	_c.Call.Return(run)
	return _c
}

// OCSP provides a mock function with given fields: ctx, serialNumber
func (_m *MockService) OCSP(ctx context.Context, serialNumber string) (*certs.Certificate, int, *x509.Certificate, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for OCSP")
	}

	var r0 *certs.Certificate
	var r1 int
	var r2 *x509.Certificate
	var r3 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*certs.Certificate, int, *x509.Certificate, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *certs.Certificate); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*certs.Certificate)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) int); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string) *x509.Certificate); ok {
		r2 = rf(ctx, serialNumber)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).(*x509.Certificate)
		}
	}

	if rf, ok := ret.Get(3).(func(context.Context, string) error); ok {
		r3 = rf(ctx, serialNumber)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// MockService_OCSP_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OCSP'
type MockService_OCSP_Call struct {
	*mock.Call
}

// OCSP is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockService_Expecter) OCSP(ctx interface{}, serialNumber interface{}) *MockService_OCSP_Call {
	return &MockService_OCSP_Call{Call: _e.mock.On("OCSP", ctx, serialNumber)}
}

func (_c *MockService_OCSP_Call) Run(run func(ctx context.Context, serialNumber string)) *MockService_OCSP_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_OCSP_Call) Return(_a0 *certs.Certificate, _a1 int, _a2 *x509.Certificate, _a3 error) *MockService_OCSP_Call {
	_c.Call.Return(_a0, _a1, _a2, _a3)
	return _c
}

func (_c *MockService_OCSP_Call) RunAndReturn(run func(context.Context, string) (*certs.Certificate, int, *x509.Certificate, error)) *MockService_OCSP_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveCert provides a mock function with given fields: ctx, entityId
func (_m *MockService) RemoveCert(ctx context.Context, entityId string) error {
	ret := _m.Called(ctx, entityId)

	if len(ret) == 0 {
		panic("no return value specified for RemoveCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, entityId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockService_RemoveCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveCert'
type MockService_RemoveCert_Call struct {
	*mock.Call
}

// RemoveCert is a helper method to define mock.On call
//   - ctx context.Context
//   - entityId string
func (_e *MockService_Expecter) RemoveCert(ctx interface{}, entityId interface{}) *MockService_RemoveCert_Call {
	return &MockService_RemoveCert_Call{Call: _e.mock.On("RemoveCert", ctx, entityId)}
}

func (_c *MockService_RemoveCert_Call) Run(run func(ctx context.Context, entityId string)) *MockService_RemoveCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_RemoveCert_Call) Return(_a0 error) *MockService_RemoveCert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockService_RemoveCert_Call) RunAndReturn(run func(context.Context, string) error) *MockService_RemoveCert_Call {
	_c.Call.Return(run)
	return _c
}

// RenewCert provides a mock function with given fields: ctx, serialNumber
func (_m *MockService) RenewCert(ctx context.Context, serialNumber string) error {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RenewCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockService_RenewCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RenewCert'
type MockService_RenewCert_Call struct {
	*mock.Call
}

// RenewCert is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockService_Expecter) RenewCert(ctx interface{}, serialNumber interface{}) *MockService_RenewCert_Call {
	return &MockService_RenewCert_Call{Call: _e.mock.On("RenewCert", ctx, serialNumber)}
}

func (_c *MockService_RenewCert_Call) Run(run func(ctx context.Context, serialNumber string)) *MockService_RenewCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_RenewCert_Call) Return(_a0 error) *MockService_RenewCert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockService_RenewCert_Call) RunAndReturn(run func(context.Context, string) error) *MockService_RenewCert_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveCAToken provides a mock function with given fields: ctx
func (_m *MockService) RetrieveCAToken(ctx context.Context) (string, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveCAToken")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (string, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) string); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_RetrieveCAToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveCAToken'
type MockService_RetrieveCAToken_Call struct {
	*mock.Call
}

// RetrieveCAToken is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockService_Expecter) RetrieveCAToken(ctx interface{}) *MockService_RetrieveCAToken_Call {
	return &MockService_RetrieveCAToken_Call{Call: _e.mock.On("RetrieveCAToken", ctx)}
}

func (_c *MockService_RetrieveCAToken_Call) Run(run func(ctx context.Context)) *MockService_RetrieveCAToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockService_RetrieveCAToken_Call) Return(_a0 string, _a1 error) *MockService_RetrieveCAToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_RetrieveCAToken_Call) RunAndReturn(run func(context.Context) (string, error)) *MockService_RetrieveCAToken_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveCert provides a mock function with given fields: ctx, token, serialNumber
func (_m *MockService) RetrieveCert(ctx context.Context, token string, serialNumber string) (certs.Certificate, []byte, error) {
	ret := _m.Called(ctx, token, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveCert")
	}

	var r0 certs.Certificate
	var r1 []byte
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (certs.Certificate, []byte, error)); ok {
		return rf(ctx, token, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) certs.Certificate); ok {
		r0 = rf(ctx, token, serialNumber)
	} else {
		r0 = ret.Get(0).(certs.Certificate)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) []byte); ok {
		r1 = rf(ctx, token, serialNumber)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string) error); ok {
		r2 = rf(ctx, token, serialNumber)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockService_RetrieveCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveCert'
type MockService_RetrieveCert_Call struct {
	*mock.Call
}

// RetrieveCert is a helper method to define mock.On call
//   - ctx context.Context
//   - token string
//   - serialNumber string
func (_e *MockService_Expecter) RetrieveCert(ctx interface{}, token interface{}, serialNumber interface{}) *MockService_RetrieveCert_Call {
	return &MockService_RetrieveCert_Call{Call: _e.mock.On("RetrieveCert", ctx, token, serialNumber)}
}

func (_c *MockService_RetrieveCert_Call) Run(run func(ctx context.Context, token string, serialNumber string)) *MockService_RetrieveCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockService_RetrieveCert_Call) Return(_a0 certs.Certificate, _a1 []byte, _a2 error) *MockService_RetrieveCert_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockService_RetrieveCert_Call) RunAndReturn(run func(context.Context, string, string) (certs.Certificate, []byte, error)) *MockService_RetrieveCert_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveCertDownloadToken provides a mock function with given fields: ctx, serialNumber
func (_m *MockService) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveCertDownloadToken")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_RetrieveCertDownloadToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveCertDownloadToken'
type MockService_RetrieveCertDownloadToken_Call struct {
	*mock.Call
}

// RetrieveCertDownloadToken is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockService_Expecter) RetrieveCertDownloadToken(ctx interface{}, serialNumber interface{}) *MockService_RetrieveCertDownloadToken_Call {
	return &MockService_RetrieveCertDownloadToken_Call{Call: _e.mock.On("RetrieveCertDownloadToken", ctx, serialNumber)}
}

func (_c *MockService_RetrieveCertDownloadToken_Call) Run(run func(ctx context.Context, serialNumber string)) *MockService_RetrieveCertDownloadToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_RetrieveCertDownloadToken_Call) Return(_a0 string, _a1 error) *MockService_RetrieveCertDownloadToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_RetrieveCertDownloadToken_Call) RunAndReturn(run func(context.Context, string) (string, error)) *MockService_RetrieveCertDownloadToken_Call {
	_c.Call.Return(run)
	return _c
}

// RevokeCert provides a mock function with given fields: ctx, serialNumber
func (_m *MockService) RevokeCert(ctx context.Context, serialNumber string) error {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RevokeCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockService_RevokeCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RevokeCert'
type MockService_RevokeCert_Call struct {
	*mock.Call
}

// RevokeCert is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockService_Expecter) RevokeCert(ctx interface{}, serialNumber interface{}) *MockService_RevokeCert_Call {
	return &MockService_RevokeCert_Call{Call: _e.mock.On("RevokeCert", ctx, serialNumber)}
}

func (_c *MockService_RevokeCert_Call) Run(run func(ctx context.Context, serialNumber string)) *MockService_RevokeCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_RevokeCert_Call) Return(_a0 error) *MockService_RevokeCert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockService_RevokeCert_Call) RunAndReturn(run func(context.Context, string) error) *MockService_RevokeCert_Call {
	_c.Call.Return(run)
	return _c
}

// SignCSR provides a mock function with given fields: ctx, entityID, ttl, csr
func (_m *MockService) SignCSR(ctx context.Context, entityID string, ttl string, csr certs.CSR) (certs.Certificate, error) {
	ret := _m.Called(ctx, entityID, ttl, csr)

	if len(ret) == 0 {
		panic("no return value specified for SignCSR")
	}

	var r0 certs.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, certs.CSR) (certs.Certificate, error)); ok {
		return rf(ctx, entityID, ttl, csr)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, certs.CSR) certs.Certificate); ok {
		r0 = rf(ctx, entityID, ttl, csr)
	} else {
		r0 = ret.Get(0).(certs.Certificate)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, certs.CSR) error); ok {
		r1 = rf(ctx, entityID, ttl, csr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_SignCSR_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SignCSR'
type MockService_SignCSR_Call struct {
	*mock.Call
}

// SignCSR is a helper method to define mock.On call
//   - ctx context.Context
//   - entityID string
//   - ttl string
//   - csr certs.CSR
func (_e *MockService_Expecter) SignCSR(ctx interface{}, entityID interface{}, ttl interface{}, csr interface{}) *MockService_SignCSR_Call {
	return &MockService_SignCSR_Call{Call: _e.mock.On("SignCSR", ctx, entityID, ttl, csr)}
}

func (_c *MockService_SignCSR_Call) Run(run func(ctx context.Context, entityID string, ttl string, csr certs.CSR)) *MockService_SignCSR_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(certs.CSR))
	})
	return _c
}

func (_c *MockService_SignCSR_Call) Return(_a0 certs.Certificate, _a1 error) *MockService_SignCSR_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_SignCSR_Call) RunAndReturn(run func(context.Context, string, string, certs.CSR) (certs.Certificate, error)) *MockService_SignCSR_Call {
	_c.Call.Return(run)
	return _c
}

// ViewCert provides a mock function with given fields: ctx, serialNumber
func (_m *MockService) ViewCert(ctx context.Context, serialNumber string) (certs.Certificate, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for ViewCert")
	}

	var r0 certs.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (certs.Certificate, error)); ok {
		return rf(ctx, serialNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) certs.Certificate); ok {
		r0 = rf(ctx, serialNumber)
	} else {
		r0 = ret.Get(0).(certs.Certificate)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, serialNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockService_ViewCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ViewCert'
type MockService_ViewCert_Call struct {
	*mock.Call
}

// ViewCert is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockService_Expecter) ViewCert(ctx interface{}, serialNumber interface{}) *MockService_ViewCert_Call {
	return &MockService_ViewCert_Call{Call: _e.mock.On("ViewCert", ctx, serialNumber)}
}

func (_c *MockService_ViewCert_Call) Run(run func(ctx context.Context, serialNumber string)) *MockService_ViewCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockService_ViewCert_Call) Return(_a0 certs.Certificate, _a1 error) *MockService_ViewCert_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockService_ViewCert_Call) RunAndReturn(run func(context.Context, string) (certs.Certificate, error)) *MockService_ViewCert_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockService creates a new instance of MockService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockService(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockService {
	mock := &MockService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
