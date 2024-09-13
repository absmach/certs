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
	id          = "c333e6f1-59bb-4c39-9e13-3a2766af8ba5"
	ttl         = "10h"
	commonName  = "test"
)

func setupCerts() (*httptest.Server, *mocks.MockService) {
	svc := new(mocks.MockService)
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
		svcresp    string
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
			svcresp:    serialNum,
			sdkCert: sdk.Certificate{
				SerialNumber: serialNum,
			},
			svcerr: nil,
			err:    nil,
		},
		{
			desc:     "IssueCert failure",
			entityID: id,
			ttl:      ttl,
			ipAddrs:  ipAddr,
			commonName: commonName,
			svcresp:  "",
			svcerr:   certs.ErrCreateEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:     "IssueCert with empty entityID",
			entityID: `""`,
			ttl:      ttl,
			ipAddrs:  ipAddr,
			commonName: commonName,
			svcresp:  "",
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
		{
			desc:     "IssueCert with empty ipAddrs",
			entityID: id,
			ttl:      ttl,
			commonName: commonName,
			svcresp:  serialNum,
			sdkCert: sdk.Certificate{
				SerialNumber: serialNum,
			},
			svcerr: nil,
			err:    nil,
		},
		{
			desc:     "IssueCert with empty ttl",
			entityID: id,
			ttl:      "",
			ipAddrs:  ipAddr,
			commonName: commonName,
			svcresp:  serialNum,
			sdkCert: sdk.Certificate{
				SerialNumber: serialNum,
			},
			svcerr: nil,
			err:    nil,
		},
		{
			desc:     "IssueCert with empty commonName",
			entityID: id,
			ttl:      ttl,
			ipAddrs:  ipAddr,
			commonName: "",
			svcresp:  "",
			svcerr:   httpapi.ErrMissingCN,
			err:      errors.NewSDKErrorWithStatus(httpapi.ErrMissingCN, http.StatusBadRequest),
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
			svcCall := svc.On("RevokeCert", mock.Anything, tc.serial).Return(tc.svcerr)

			err := ctsdk.RevokeCert(tc.serial)
			assert.Equal(t, tc.err, err)
			if tc.desc != "RevokeCert with empty serial" {
				ok := svcCall.Parent.AssertCalled(t, "RevokeCert", mock.Anything, tc.serial)
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
		desc    string
		serial  string
		svcresp string
		svcerr  error
		err     errors.SDKError
	}{
		{
			desc:   "RenewCert success",
			serial: serialNum,
			svcerr: nil,
			err:    nil,
		},
		{
			desc:   "RenewCert failure",
			serial: serialNum,
			svcerr: certs.ErrUpdateEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc:   "RenewCert with empty serial",
			serial: "",
			svcerr: certs.ErrMalformedEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("RenewCert", mock.Anything, tc.serial).Return(tc.svcerr)

			err := ctsdk.RenewCert(tc.serial)
			assert.Equal(t, tc.err, err)
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
