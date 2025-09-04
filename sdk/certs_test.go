// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/absmach/certs"
	httpapi "github.com/absmach/certs/api/http"
	"github.com/absmach/certs/errors"
	"github.com/absmach/certs/mocks"
	"github.com/absmach/certs/sdk"
	logger "github.com/absmach/certs/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	instanceID  = "5de9b29a-feb9-11ed-be56-0242ac120002"
	contentType = "application/senml+json"
	serialNum   = "8e7a30c-bc9f-22de-ae67-1342bc139507"
	id          = "c333e6f-59bb-4c39-9e13-3a2766af8ba5"
	ttl         = "10h"
	commonName  = "test"
	token       = "token"
)

func setupCerts() (*httptest.Server, *mocks.Service) {
	svc := new(mocks.Service)
	logger := logger.NewMock()
	mux := httpapi.MakeHandler(svc, logger, instanceID)

	return httptest.NewServer(mux), svc
}

func TestIssueCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	ipAddr := []string{"192.128.101.82"}
	cases := []struct {
		desc       string
		entityID   string
		ttl        string
		ipAddrs    []string
		commonName string
		svcresp    certs.Certificate
		svcerr     error
		err        errors.SDKError
		sdkCert    sdk.Certificate
	}{
		{
			desc:       "IssueCert success",
			entityID:   id,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: commonName,
			svcresp: certs.Certificate{
				SerialNumber: serialNum,
			},
			sdkCert: sdk.Certificate{
				SerialNumber: serialNum,
			},
			svcerr: nil,
			err:    nil,
		},
		{
			desc:       "IssueCert failure",
			entityID:   id,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: commonName,
			svcresp:    certs.Certificate{},
			svcerr:     certs.ErrCreateEntity,
			err:        errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:       "IssueCert with empty entityID",
			entityID:   `""`,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: commonName,
			svcresp:    certs.Certificate{},
			svcerr:     certs.ErrMalformedEntity,
			err:        errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
		{
			desc:       "IssueCert with empty ipAddrs",
			entityID:   id,
			ttl:        ttl,
			commonName: commonName,
			svcresp:    certs.Certificate{SerialNumber: serialNum},
			sdkCert: sdk.Certificate{
				SerialNumber: serialNum,
			},
			svcerr: nil,
			err:    nil,
		},
		{
			desc:       "IssueCert with empty ttl",
			entityID:   id,
			ttl:        "",
			ipAddrs:    ipAddr,
			commonName: commonName,
			svcresp:    certs.Certificate{SerialNumber: serialNum},
			sdkCert: sdk.Certificate{
				SerialNumber: serialNum,
			},
			svcerr: nil,
			err:    nil,
		},
		{
			desc:       "IssueCert with empty commonName",
			entityID:   id,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: "",
			svcresp:    certs.Certificate{},
			svcerr:     httpapi.ErrMissingCN,
			err:        errors.NewSDKErrorWithStatus(httpapi.ErrMissingCN, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("IssueCert", mock.Anything, tc.entityID, tc.ttl, tc.ipAddrs, mock.Anything).Return(tc.svcresp, tc.svcerr)

			resp, err := ctsdk.IssueCert(tc.entityID, tc.ttl, tc.ipAddrs, sdk.Options{CommonName: tc.commonName})
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.sdkCert.SerialNumber, resp.SerialNumber)
				ok := svcCall.Parent.AssertCalled(t, "IssueCert", mock.Anything, tc.entityID, tc.ttl, tc.ipAddrs, certs.SubjectOptions{CommonName: tc.commonName})
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestRevokeCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc    string
		serial  string
		svcresp string
		svcerr  error
		err     errors.SDKError
	}{
		{
			desc:   "RevokeCert success",
			serial: serialNum,
			svcerr: nil,
			err:    nil,
		},
		{
			desc:   "RevokeCert failure",
			serial: serialNum,
			svcerr: certs.ErrUpdateEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:   "RevokeCert with empty serial",
			serial: "",
			svcerr: certs.ErrMalformedEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RevokeBySerial", mock.Anything, tc.serial).Return(tc.svcerr)

			err := ctsdk.RevokeCert(tc.serial)
			assert.Equal(t, tc.err, err)
			if tc.desc != "RevokeCert with empty serial" {
				ok := svcCall.Parent.AssertCalled(t, "RevokeBySerial", mock.Anything, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestDeleteCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc     string
		entityID string
		svcresp  string
		svcerr   error
		err      errors.SDKError
	}{
		{
			desc:     "DeleteCert success",
			entityID: id,
			svcerr:   nil,
			err:      nil,
		},
		{
			desc:     "DeleteCert failure",
			entityID: id,
			svcerr:   certs.ErrUpdateEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:     "DeleteCert with empty entity id",
			entityID: "",
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RevokeAll", mock.Anything, tc.entityID).Return(tc.svcerr)

			err := ctsdk.DeleteCert(tc.entityID)
			assert.Equal(t, tc.err, err)
			if tc.desc != "DeleteCert with empty entity id" {
				ok := svcCall.Parent.AssertCalled(t, "RevokeAll", mock.Anything, tc.entityID)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestRenewCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc     string
		serial   string
		svcresp  certs.Certificate
		svcerr   error
		err      errors.SDKError
		expected sdk.Certificate
	}{
		{
			desc:   "RenewCert success",
			serial: serialNum,
			svcresp: certs.Certificate{
				SerialNumber: "new-serial-123",
				EntityID:     "test-entity",
			},
			svcerr: nil,
			err:    nil,
			expected: sdk.Certificate{
				SerialNumber: "new-serial-123",
				EntityID:     "test-entity",
			},
		},
		{
			desc:     "RenewCert failure",
			serial:   serialNum,
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrUpdateEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			expected: sdk.Certificate{},
		},
		{
			desc:     "RenewCert with empty serial",
			serial:   "",
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			expected: sdk.Certificate{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RenewCert", mock.Anything, tc.serial).Return(tc.svcresp, tc.svcerr)

			cert, err := ctsdk.RenewCert(tc.serial)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.expected, cert)
			} else {
				assert.Equal(t, sdk.Certificate{}, cert)
			}
			if tc.desc != "RenewCert with empty serial" {
				ok := svcCall.Parent.AssertCalled(t, "RenewCert", mock.Anything, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestListCerts(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc    string
		svcResp certs.CertificatePage
		sdkPm   sdk.PageMetadata
		svcerr  error
		err     errors.SDKError
	}{
		{
			desc: "ListCerts success",
			sdkPm: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcResp: certs.CertificatePage{
				PageMetadata: certs.PageMetadata{
					Total:  1,
					Offset: 0,
					Limit:  10,
				},
				Certificates: []certs.Certificate{
					{
						SerialNumber: serialNum,
					},
				},
			},
		},
		{
			desc: "ListCerts success with entity id",
			sdkPm: sdk.PageMetadata{
				Offset:   0,
				Limit:    10,
				EntityID: id,
			},
			svcResp: certs.CertificatePage{
				PageMetadata: certs.PageMetadata{
					Total:  1,
					Offset: 0,
					Limit:  10,
				},
				Certificates: []certs.Certificate{
					{
						SerialNumber: serialNum,
						EntityID:     id,
					},
				},
			},
		},
		{
			desc: "ListCerts failure",
			sdkPm: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcerr: certs.ErrViewEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("ListCerts", mock.Anything, mock.Anything).Return(tc.svcResp, tc.svcerr)

			resp, err := ctsdk.ListCerts(tc.sdkPm)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.svcResp.Total, resp.Total)
				assert.Equal(t, tc.svcResp.Certificates[0].SerialNumber, resp.Certificates[0].SerialNumber)
				if tc.desc == "ListCerts success with entity id" {
					assert.Equal(t, tc.svcResp.Certificates[0].EntityID, resp.Certificates[0].EntityID)
				}
			}
			svcCall.Unset()
		})
	}
}

func TestRetrieveCertDownloadToken(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	token := "valid token"

	cases := []struct {
		desc    string
		serial  string
		svcresp string
		svcerr  error
		err     errors.SDKError
	}{
		{
			desc:    "RetrieveCertDownloadToken success",
			serial:  serialNum,
			svcresp: token,
			svcerr:  nil,
			err:     nil,
		},
		{
			desc:    "RetrieveCertDownloadToken failure",
			serial:  serialNum,
			svcresp: "",
			svcerr:  certs.ErrGetToken,
			err:     errors.NewSDKErrorWithStatus(certs.ErrGetToken, http.StatusUnprocessableEntity),
		},
		{
			desc:    "RetrieveCertDownloadToken with empty serial",
			serial:  "",
			svcresp: "",
			svcerr:  certs.ErrMalformedEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RetrieveCertDownloadToken", mock.Anything, tc.serial).Return(tc.svcresp, tc.svcerr)

			resp, err := ctsdk.RetrieveCertDownloadToken(tc.serial)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.svcresp, resp.Token)
				ok := svcCall.Parent.AssertCalled(t, "RetrieveCertDownloadToken", mock.Anything, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestDownloadCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	token := "token"
	cert := sdk.Certificate{
		SerialNumber: serialNum,
	}

	cases := []struct {
		desc    string
		token   string
		serial  string
		svcresp certs.Certificate
		svcerr  error
		err     errors.SDKError
		sdkCert sdk.Certificate
	}{
		{
			desc:   "DownloadCert success",
			token:  token,
			serial: serialNum,
			svcresp: certs.Certificate{
				SerialNumber: serialNum,
			},
			sdkCert: cert,
			svcerr:  nil,
			err:     nil,
		},
		{
			desc:    "DownloadCert failure",
			token:   token,
			serial:  serialNum,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrViewEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:    "DownloadCert with empty token",
			token:   "",
			serial:  serialNum,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrMalformedEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
		{
			desc:    "DownloadCert with empty serial",
			token:   token,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrMalformedEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RetrieveCert", mock.Anything, tc.token, tc.serial).Return(tc.svcresp, []byte{}, tc.svcerr)

			_, err := ctsdk.DownloadCert(tc.token, tc.serial)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "RetrieveCert", mock.Anything, tc.token, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestViewCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cert := sdk.Certificate{
		SerialNumber: serialNum,
	}

	cases := []struct {
		desc    string
		serial  string
		svcresp certs.Certificate
		svcerr  error
		err     errors.SDKError
		sdkCert sdk.Certificate
	}{
		{
			desc:   "ViewCert success",
			serial: serialNum,
			svcresp: certs.Certificate{
				SerialNumber: serialNum,
			},
			sdkCert: cert,
			svcerr:  nil,
			err:     nil,
		},
		{
			desc:    "ViewCert failure",
			serial:  serialNum,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrViewEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("ViewCert", mock.Anything, tc.serial).Return(tc.svcresp, tc.svcerr)

			c, err := ctsdk.ViewCert(tc.serial)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "ViewCert", mock.Anything, tc.serial)
				assert.True(t, ok)
			}
			assert.Equal(t, tc.sdkCert.SerialNumber, c.SerialNumber, fmt.Sprintf("expected: %v, got: %v", tc.sdkCert.SerialNumber, c.SerialNumber))
			svcCall.Unset()
		})
	}
}

func TestDownloadCACert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cert := sdk.Certificate{
		SerialNumber: serialNum,
	}

	cases := []struct {
		desc    string
		token   string
		svcresp certs.Certificate
		svcerr  error
		err     errors.SDKError
		sdkCert sdk.Certificate
	}{
		{
			desc:  "Download CA successfully",
			token: token,
			svcresp: certs.Certificate{
				SerialNumber: serialNum,
				Certificate:  []byte("cert"),
				Key:          []byte("key"),
			},
			sdkCert: cert,
			svcerr:  nil,
			err:     nil,
		},
		{
			desc:    "Download CA failure",
			token:   token,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrViewEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:    "Download CA with empty token",
			token:   "",
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrMalformedEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("GetChainCA", mock.Anything, tc.token).Return(tc.svcresp, tc.svcerr)

			_, err := ctsdk.DownloadCA(tc.token)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "GetChainCA", mock.Anything, tc.token)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestViewCA(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cert := sdk.Certificate{
		SerialNumber: serialNum,
		Certificate:  "cert",
		Key:          "Key",
	}

	cases := []struct {
		desc    string
		token   string
		svcresp certs.Certificate
		svcerr  error
		err     errors.SDKError
		sdkCert sdk.Certificate
	}{
		{
			desc:  "ViewCA success",
			token: token,
			svcresp: certs.Certificate{
				Certificate: []byte("cert"),
			},
			sdkCert: cert,
			svcerr:  nil,
			err:     nil,
		},
		{
			desc:    "ViewCA failure",
			token:   token,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrViewEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("GetChainCA", mock.Anything, tc.token).Return(tc.svcresp, tc.svcerr)

			c, err := ctsdk.ViewCA(tc.token)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "GetChainCA", mock.Anything, tc.token)
				assert.True(t, ok)
			}
			assert.Equal(t, tc.sdkCert.Certificate, c.Certificate, fmt.Sprintf("expected: %v, got: %v", tc.sdkCert.Certificate, c.Certificate))
			svcCall.Unset()
		})
	}
}

func TestGetCAToken(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	token := "valid token"

	cases := []struct {
		desc    string
		svcresp string
		svcerr  error
		err     errors.SDKError
	}{
		{
			desc:    "RetrieveCertDownloadToken success",
			svcresp: token,
			svcerr:  nil,
			err:     nil,
		},
		{
			desc:    "RetrieveCertDownloadToken failure",
			svcresp: "",
			svcerr:  certs.ErrGetToken,
			err:     errors.NewSDKErrorWithStatus(certs.ErrGetToken, http.StatusUnprocessableEntity),
		},
		{
			desc:    "RetrieveCertDownloadToken with empty serial",
			svcresp: "",
			svcerr:  certs.ErrMalformedEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RetrieveCAToken", mock.Anything).Return(tc.svcresp, tc.svcerr)

			resp, err := ctsdk.GetCAToken()
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.svcresp, resp.Token)
				ok := svcCall.Parent.AssertCalled(t, "RetrieveCAToken", mock.Anything)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}
