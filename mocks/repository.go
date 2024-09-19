// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	context "context"

	certs "github.com/absmach/certs"

	mock "github.com/stretchr/testify/mock"
)

// MockRepository is an autogenerated mock type for the Repository type
type MockRepository struct {
	mock.Mock
}

type MockRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *MockRepository) EXPECT() *MockRepository_Expecter {
	return &MockRepository_Expecter{mock: &_m.Mock}
}

// CreateCert provides a mock function with given fields: ctx, cert
func (_m *MockRepository) CreateCert(ctx context.Context, cert certs.Certificate) error {
	ret := _m.Called(ctx, cert)

	if len(ret) == 0 {
		panic("no return value specified for CreateCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, certs.Certificate) error); ok {
		r0 = rf(ctx, cert)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockRepository_CreateCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateCert'
type MockRepository_CreateCert_Call struct {
	*mock.Call
}

// CreateCert is a helper method to define mock.On call
//   - ctx context.Context
//   - cert certs.Certificate
func (_e *MockRepository_Expecter) CreateCert(ctx interface{}, cert interface{}) *MockRepository_CreateCert_Call {
	return &MockRepository_CreateCert_Call{Call: _e.mock.On("CreateCert", ctx, cert)}
}

func (_c *MockRepository_CreateCert_Call) Run(run func(ctx context.Context, cert certs.Certificate)) *MockRepository_CreateCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(certs.Certificate))
	})
	return _c
}

func (_c *MockRepository_CreateCert_Call) Return(_a0 error) *MockRepository_CreateCert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepository_CreateCert_Call) RunAndReturn(run func(context.Context, certs.Certificate) error) *MockRepository_CreateCert_Call {
	_c.Call.Return(run)
	return _c
}

// GetCAs provides a mock function with given fields: ctx, caType
func (_m *MockRepository) GetCAs(ctx context.Context, caType ...certs.CertType) ([]certs.Certificate, error) {
	_va := make([]interface{}, len(caType))
	for _i := range caType {
		_va[_i] = caType[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for GetCAs")
	}

	var r0 []certs.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...certs.CertType) ([]certs.Certificate, error)); ok {
		return rf(ctx, caType...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...certs.CertType) []certs.Certificate); ok {
		r0 = rf(ctx, caType...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]certs.Certificate)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...certs.CertType) error); ok {
		r1 = rf(ctx, caType...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockRepository_GetCAs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCAs'
type MockRepository_GetCAs_Call struct {
	*mock.Call
}

// GetCAs is a helper method to define mock.On call
//   - ctx context.Context
//   - caType ...certs.CertType
func (_e *MockRepository_Expecter) GetCAs(ctx interface{}, caType ...interface{}) *MockRepository_GetCAs_Call {
	return &MockRepository_GetCAs_Call{Call: _e.mock.On("GetCAs",
		append([]interface{}{ctx}, caType...)...)}
}

func (_c *MockRepository_GetCAs_Call) Run(run func(ctx context.Context, caType ...certs.CertType)) *MockRepository_GetCAs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]certs.CertType, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(certs.CertType)
			}
		}
		run(args[0].(context.Context), variadicArgs...)
	})
	return _c
}

func (_c *MockRepository_GetCAs_Call) Return(_a0 []certs.Certificate, _a1 error) *MockRepository_GetCAs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockRepository_GetCAs_Call) RunAndReturn(run func(context.Context, ...certs.CertType) ([]certs.Certificate, error)) *MockRepository_GetCAs_Call {
	_c.Call.Return(run)
	return _c
}

// ListCerts provides a mock function with given fields: ctx, pm
func (_m *MockRepository) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
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

// MockRepository_ListCerts_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListCerts'
type MockRepository_ListCerts_Call struct {
	*mock.Call
}

// ListCerts is a helper method to define mock.On call
//   - ctx context.Context
//   - pm certs.PageMetadata
func (_e *MockRepository_Expecter) ListCerts(ctx interface{}, pm interface{}) *MockRepository_ListCerts_Call {
	return &MockRepository_ListCerts_Call{Call: _e.mock.On("ListCerts", ctx, pm)}
}

func (_c *MockRepository_ListCerts_Call) Run(run func(ctx context.Context, pm certs.PageMetadata)) *MockRepository_ListCerts_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(certs.PageMetadata))
	})
	return _c
}

func (_c *MockRepository_ListCerts_Call) Return(_a0 certs.CertificatePage, _a1 error) *MockRepository_ListCerts_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockRepository_ListCerts_Call) RunAndReturn(run func(context.Context, certs.PageMetadata) (certs.CertificatePage, error)) *MockRepository_ListCerts_Call {
	_c.Call.Return(run)
	return _c
}

// ListRevokedCerts provides a mock function with given fields: ctx
func (_m *MockRepository) ListRevokedCerts(ctx context.Context) ([]certs.Certificate, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListRevokedCerts")
	}

	var r0 []certs.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]certs.Certificate, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []certs.Certificate); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]certs.Certificate)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockRepository_ListRevokedCerts_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListRevokedCerts'
type MockRepository_ListRevokedCerts_Call struct {
	*mock.Call
}

// ListRevokedCerts is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockRepository_Expecter) ListRevokedCerts(ctx interface{}) *MockRepository_ListRevokedCerts_Call {
	return &MockRepository_ListRevokedCerts_Call{Call: _e.mock.On("ListRevokedCerts", ctx)}
}

func (_c *MockRepository_ListRevokedCerts_Call) Run(run func(ctx context.Context)) *MockRepository_ListRevokedCerts_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockRepository_ListRevokedCerts_Call) Return(_a0 []certs.Certificate, _a1 error) *MockRepository_ListRevokedCerts_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockRepository_ListRevokedCerts_Call) RunAndReturn(run func(context.Context) ([]certs.Certificate, error)) *MockRepository_ListRevokedCerts_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveCert provides a mock function with given fields: ctx, serialNumber
func (_m *MockRepository) RetrieveCert(ctx context.Context, serialNumber string) (certs.Certificate, error) {
	ret := _m.Called(ctx, serialNumber)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveCert")
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

// MockRepository_RetrieveCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveCert'
type MockRepository_RetrieveCert_Call struct {
	*mock.Call
}

// RetrieveCert is a helper method to define mock.On call
//   - ctx context.Context
//   - serialNumber string
func (_e *MockRepository_Expecter) RetrieveCert(ctx interface{}, serialNumber interface{}) *MockRepository_RetrieveCert_Call {
	return &MockRepository_RetrieveCert_Call{Call: _e.mock.On("RetrieveCert", ctx, serialNumber)}
}

func (_c *MockRepository_RetrieveCert_Call) Run(run func(ctx context.Context, serialNumber string)) *MockRepository_RetrieveCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockRepository_RetrieveCert_Call) Return(_a0 certs.Certificate, _a1 error) *MockRepository_RetrieveCert_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockRepository_RetrieveCert_Call) RunAndReturn(run func(context.Context, string) (certs.Certificate, error)) *MockRepository_RetrieveCert_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateCert provides a mock function with given fields: ctx, cert
func (_m *MockRepository) UpdateCert(ctx context.Context, cert certs.Certificate) error {
	ret := _m.Called(ctx, cert)

	if len(ret) == 0 {
		panic("no return value specified for UpdateCert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, certs.Certificate) error); ok {
		r0 = rf(ctx, cert)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockRepository_UpdateCert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateCert'
type MockRepository_UpdateCert_Call struct {
	*mock.Call
}

// UpdateCert is a helper method to define mock.On call
//   - ctx context.Context
//   - cert certs.Certificate
func (_e *MockRepository_Expecter) UpdateCert(ctx interface{}, cert interface{}) *MockRepository_UpdateCert_Call {
	return &MockRepository_UpdateCert_Call{Call: _e.mock.On("UpdateCert", ctx, cert)}
}

func (_c *MockRepository_UpdateCert_Call) Run(run func(ctx context.Context, cert certs.Certificate)) *MockRepository_UpdateCert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(certs.Certificate))
	})
	return _c
}

func (_c *MockRepository_UpdateCert_Call) Return(_a0 error) *MockRepository_UpdateCert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepository_UpdateCert_Call) RunAndReturn(run func(context.Context, certs.Certificate) error) *MockRepository_UpdateCert_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockRepository creates a new instance of MockRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockRepository {
	mock := &MockRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
