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
	"github.com/absmach/certs/mocks"
	"github.com/absmach/certs/sdk"
	logger "github.com/absmach/certs/sdk/mocks"
	smqauthn "github.com/absmach/supermq/pkg/authn"
	authnmocks "github.com/absmach/supermq/pkg/authn/mocks"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	instanceID  = "5de9b29a-feb9-11ed-be56-0242ac120002"
	contentType = "application/senml+json"
	serialNum   = "8e7a30c-bc9f-22de-ae67-1342bc139507"
	id          = "c333e6f-59bb-4c39-9e13-3a2766af8ba5"
	validID     = "c333e6f-59bb-4c39-9e13-3a2766af8ba5"
	ttl         = "10h"
	commonName  = "test"
	token       = "token"
	domainID    = "domain-id"
)

func setupCerts() (*httptest.Server, *mocks.Service, *authnmocks.Authentication) {
	svc := new(mocks.Service)
	mux := chi.NewRouter()
	logger := logger.NewMock()
	authn := new(authnmocks.Authentication)
	handler := httpapi.MakeHandler(svc, authn, mux, logger, instanceID, "")

	return httptest.NewServer(handler), svc, authn
}

func TestIssueCert(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	ipAddr := []string{"192.128.101.82"}
	cases := []struct {
		desc            string
		entityID        string
		ttl             string
		ipAddrs         []string
		commonName      string
		svcresp         certs.Certificate
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		sdkCert         sdk.Certificate
		domain          string
		token           string
		session         smqauthn.Session
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
			domain: domainID,
			token:  token,
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
			domain:     domainID,
			token:      token,
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
			domain:     domainID,
			token:      token,
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
			domain: domainID,
			token:  token,
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
			domain: domainID,
			token:  token,
		},
		{
			desc:       "IssueCert with empty commonName",
			entityID:   id,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: "",
			svcresp:    certs.Certificate{},
			svcerr:     certs.ErrMalformedEntity,
			err:        errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			domain:     domainID,
			token:      token,
		},
		{
			desc:       "IssueCert with empty token",
			entityID:   id,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: commonName,
			svcresp:    certs.Certificate{},
			svcerr:     nil,
			err:        errors.NewSDKErrorWithStatus(errors.New("missing or invalid bearer user token"), http.StatusUnauthorized),
			domain:     domainID,
			token:      "",
		},
		{
			desc:       "IssueCert with empty domain",
			entityID:   id,
			ttl:        ttl,
			ipAddrs:    ipAddr,
			commonName: commonName,
			svcresp:    certs.Certificate{},
			svcerr:     nil,
			err:        errors.NewSDKErrorWithStatus(errors.New("missing domainID"), http.StatusBadRequest),
			domain:     "",
			token:      token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("IssueCert", mock.Anything, tc.session, tc.entityID, tc.ttl, tc.ipAddrs, certs.SubjectOptions{CommonName: tc.commonName}).Return(tc.svcresp, tc.svcerr)
			resp, err := ctsdk.IssueCert(tc.entityID, tc.ttl, tc.ipAddrs, sdk.Options{CommonName: tc.commonName}, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.sdkCert.SerialNumber, resp.SerialNumber)
				ok := svcCall.Parent.AssertCalled(t, "IssueCert", mock.Anything, tc.session, tc.entityID, tc.ttl, tc.ipAddrs, certs.SubjectOptions{CommonName: tc.commonName})
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestRevokeCert(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc            string
		serial          string
		svcresp         string
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		domain          string
		token           string
		session         smqauthn.Session
	}{
		{
			desc:   "RevokeCert success",
			serial: serialNum,
			svcerr: nil,
			err:    nil,
			domain: domainID,
			token:  token,
		},
		{
			desc:   "RevokeCert failure",
			serial: serialNum,
			svcerr: certs.ErrUpdateEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			domain: domainID,
			token:  token,
		},
		{
			desc:   "RevokeCert with empty serial",
			serial: "",
			svcerr: certs.ErrMalformedEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			domain: domainID,
			token:  token,
		},
		{
			desc:   "RevokeCert with empty token",
			serial: serialNum,
			svcerr: nil,
			err:    errors.NewSDKErrorWithStatus(errors.New("missing or invalid bearer user token"), http.StatusUnauthorized),
			domain: domainID,
			token:  "",
		},
		{
			desc:   "RevokeCert with empty domain",
			serial: serialNum,
			svcerr: nil,
			err:    errors.NewSDKErrorWithStatus(errors.New("missing domainID"), http.StatusBadRequest),
			domain: "",
			token:  token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("RevokeBySerial", mock.Anything, tc.session, tc.serial).Return(tc.svcerr)

			err := ctsdk.RevokeCert(tc.serial, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.desc != "RevokeCert with empty serial" && tc.desc != "RevokeCert with empty token" && tc.desc != "RevokeCert with empty domain" {
				ok := svcCall.Parent.AssertCalled(t, "RevokeBySerial", mock.Anything, tc.session, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestDeleteCert(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc            string
		entityID        string
		svcresp         string
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		domain          string
		token           string
		session         smqauthn.Session
	}{
		{
			desc:     "DeleteCert success",
			entityID: id,
			svcerr:   nil,
			err:      nil,
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "DeleteCert failure",
			entityID: id,
			svcerr:   certs.ErrUpdateEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "DeleteCert with empty entity id",
			entityID: "",
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "DeleteCert with empty token",
			entityID: id,
			svcerr:   nil,
			err:      errors.NewSDKErrorWithStatus(errors.New("missing or invalid bearer user token"), http.StatusUnauthorized),
			domain:   domainID,
			token:    "",
		},
		{
			desc:     "DeleteCert with empty domain",
			entityID: id,
			svcerr:   nil,
			err:      errors.NewSDKErrorWithStatus(errors.New("missing domainID"), http.StatusBadRequest),
			domain:   "",
			token:    token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("RevokeAll", mock.Anything, tc.session, tc.entityID).Return(tc.svcerr)

			err := ctsdk.DeleteCert(tc.entityID, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.desc != "DeleteCert with empty entity id" && tc.desc != "DeleteCert with empty token" && tc.desc != "DeleteCert with empty domain" {
				ok := svcCall.Parent.AssertCalled(t, "RevokeAll", mock.Anything, tc.session, tc.entityID)
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestRenewCert(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc            string
		serial          string
		svcresp         certs.Certificate
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		expected        sdk.Certificate
		domain          string
		token           string
		session         smqauthn.Session
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
			domain: domainID,
			token:  token,
		},
		{
			desc:     "RenewCert failure",
			serial:   serialNum,
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrUpdateEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			expected: sdk.Certificate{},
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "RenewCert with empty serial",
			serial:   "",
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			expected: sdk.Certificate{},
			domain:   domainID,
			token:    token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("RenewCert", mock.Anything, tc.session, tc.serial).Return(tc.svcresp, tc.svcerr)

			cert, err := ctsdk.RenewCert(tc.serial, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.expected, cert)
			} else {
				assert.Equal(t, sdk.Certificate{}, cert)
			}
			if tc.desc != "RenewCert with empty serial" {
				ok := svcCall.Parent.AssertCalled(t, "RenewCert", mock.Anything, tc.session, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestListCerts(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc            string
		svcResp         certs.CertificatePage
		sdkPm           sdk.PageMetadata
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		domain          string
		token           string
		session         smqauthn.Session
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
			domain: domainID,
			token:  token,
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
			domain: domainID,
			token:  token,
		},
		{
			desc: "ListCerts failure",
			sdkPm: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcerr: certs.ErrViewEntity,
			err:    errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			domain: domainID,
			token:  token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("ListCerts", mock.Anything, tc.session, mock.Anything).Return(tc.svcResp, tc.svcerr)

			resp, err := ctsdk.ListCerts(tc.sdkPm, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.svcResp.Total, resp.Total)
				assert.Equal(t, tc.svcResp.Certificates[0].SerialNumber, resp.Certificates[0].SerialNumber)
				if tc.desc == "ListCerts success with entity id" {
					assert.Equal(t, tc.svcResp.Certificates[0].EntityID, resp.Certificates[0].EntityID)
				}
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestViewCert(t *testing.T) {
	ts, svc, auth := setupCerts()
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
		desc            string
		serial          string
		svcresp         certs.Certificate
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		sdkCert         sdk.Certificate
		domain          string
		token           string
		session         smqauthn.Session
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
			domain:  domainID,
			token:   token,
		},
		{
			desc:    "ViewCert failure",
			serial:  serialNum,
			svcresp: certs.Certificate{},
			svcerr:  certs.ErrViewEntity,
			err:     errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			domain:  domainID,
			token:   token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("ViewCert", mock.Anything, tc.session, tc.serial).Return(tc.svcresp, tc.svcerr)

			c, err := ctsdk.ViewCert(tc.serial, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "ViewCert", mock.Anything, tc.session, tc.serial)
				assert.True(t, ok)
			}
			assert.Equal(t, tc.sdkCert.SerialNumber, c.SerialNumber, fmt.Sprintf("expected: %v, got: %v", tc.sdkCert.SerialNumber, c.SerialNumber))
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestDownloadCACert(t *testing.T) {
	ts, svc, auth := setupCerts()
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
		desc            string
		token           string
		svcresp         certs.Certificate
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		sdkCert         sdk.Certificate
		domain          string
		authToken       string
		session         smqauthn.Session
	}{
		{
			desc:  "Download CA successfully",
			token: token,
			svcresp: certs.Certificate{
				SerialNumber: serialNum,
				Certificate:  []byte("cert"),
				Key:          []byte("key"),
			},
			sdkCert:         cert,
			svcerr:          nil,
			authenticateErr: nil,
			err:             nil,
			domain:          domainID,
			authToken:       token,
			session: smqauthn.Session{
				DomainUserID: domainID + "_" + validID,
				UserID:       validID,
				DomainID:     domainID,
			},
		},
		{
			desc:            "Download CA failure",
			token:           token,
			svcresp:         certs.Certificate{},
			svcerr:          certs.ErrViewEntity,
			authenticateErr: nil,
			err:             errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			domain:          domainID,
			authToken:       token,
			session: smqauthn.Session{
				DomainUserID: domainID + "_" + validID,
				UserID:       validID,
				DomainID:     domainID,
			},
		},
		{
			desc:            "Download CA with empty token",
			token:           "",
			svcresp:         certs.Certificate{},
			svcerr:          certs.ErrMalformedEntity,
			authenticateErr: certs.ErrMalformedEntity,
			err:             errors.NewSDKErrorWithStatus(errors.New("missing or invalid bearer user token"), http.StatusUnauthorized),
			domain:          domainID,
			authToken:       "",
			session:         smqauthn.Session{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			authCall := auth.On("Authenticate", mock.Anything, tc.authToken).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("GetChainCA", mock.Anything, tc.session).Return(tc.svcresp, tc.svcerr)

			_, err := ctsdk.DownloadCA(tc.domain, tc.authToken)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "GetChainCA", mock.Anything, tc.session)
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestViewCA(t *testing.T) {
	ts, svc, auth := setupCerts()
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
		desc            string
		token           string
		svcresp         certs.Certificate
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		sdkCert         sdk.Certificate
		domain          string
		authToken       string
		session         smqauthn.Session
	}{
		{
			desc:  "ViewCA success",
			token: token,
			svcresp: certs.Certificate{
				Certificate: []byte("cert"),
			},
			sdkCert:         cert,
			svcerr:          nil,
			authenticateErr: nil,
			err:             nil,
			domain:          domainID,
			authToken:       token,
			session: smqauthn.Session{
				DomainUserID: domainID + "_" + validID,
				UserID:       validID,
				DomainID:     domainID,
			},
		},
		{
			desc:            "ViewCA failure",
			token:           token,
			svcresp:         certs.Certificate{},
			svcerr:          certs.ErrViewEntity,
			authenticateErr: nil,
			err:             errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			domain:          domainID,
			authToken:       token,
			session: smqauthn.Session{
				DomainUserID: domainID + "_" + validID,
				UserID:       validID,
				DomainID:     domainID,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			authCall := auth.On("Authenticate", mock.Anything, tc.authToken).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("GetChainCA", mock.Anything, tc.session).Return(tc.svcresp, tc.svcerr)

			c, err := ctsdk.ViewCA(tc.domain, tc.authToken)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "GetChainCA", mock.Anything, tc.session)
				assert.True(t, ok)
			}
			assert.Equal(t, tc.sdkCert.Certificate, c.Certificate, fmt.Sprintf("expected: %v, got: %v", tc.sdkCert.Certificate, c.Certificate))
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestGenerateCRL(t *testing.T) {
	ts, svc, _ := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	crlData := []byte("mock-crl-data")

	cases := []struct {
		desc     string
		certType sdk.CertType
		svcresp  []byte
		svcerr   error
		err      errors.SDKError
	}{
		{
			desc:     "GenerateCRL success for RootCA",
			certType: sdk.RootCA,
			svcresp:  crlData,
			svcerr:   nil,
			err:      nil,
		},
		{
			desc:     "GenerateCRL success for IntermediateCA",
			certType: sdk.IntermediateCA,
			svcresp:  crlData,
			svcerr:   nil,
			err:      nil,
		},
		{
			desc:     "GenerateCRL failure",
			certType: sdk.RootCA,
			svcresp:  nil,
			svcerr:   certs.ErrFailedCertCreation,
			err:      errors.NewSDKErrorWithStatus(certs.ErrFailedCertCreation, http.StatusUnprocessableEntity),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("GenerateCRL", mock.Anything, mock.Anything, mock.Anything).Return(tc.svcresp, tc.svcerr)

			resp, err := ctsdk.GenerateCRL(tc.certType)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.svcresp, resp)
				ok := svcCall.Parent.AssertCalled(t, "GenerateCRL", mock.Anything, mock.Anything, mock.Anything)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func TestRevokeAll(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc            string
		entityID        string
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		domain          string
		token           string
		session         smqauthn.Session
	}{
		{
			desc:     "RevokeAll success",
			entityID: id,
			svcerr:   nil,
			err:      nil,
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "RevokeAll failure",
			entityID: id,
			svcerr:   certs.ErrUpdateEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "RevokeAll with empty entityID",
			entityID: "",
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			domain:   domainID,
			token:    token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			svcCall := svc.On("RevokeAll", mock.Anything, tc.session, tc.entityID).Return(tc.svcerr)

			err := ctsdk.RevokeAll(tc.entityID, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			if tc.desc != "RevokeAll with empty entityID" {
				ok := svcCall.Parent.AssertCalled(t, "RevokeAll", mock.Anything, tc.session, tc.entityID)
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestGetEntityID(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	entityID := "test-entity-id"

	cases := []struct {
		desc            string
		serial          string
		svcresp         certs.Certificate
		svcerr          error
		authenticateErr error
		err             errors.SDKError
		expected        string
		domain          string
		token           string
		session         smqauthn.Session
	}{
		{
			desc:   "GetEntityID success",
			serial: serialNum,
			svcresp: certs.Certificate{
				SerialNumber: serialNum,
				EntityID:     entityID,
			},
			svcerr:   nil,
			err:      nil,
			expected: entityID,
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "GetEntityID failure",
			serial:   serialNum,
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrViewEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			expected: "",
			domain:   domainID,
			token:    token,
		},
		{
			desc:     "GetEntityID with empty serial",
			serial:   "",
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrMalformedEntity,
			err:      errors.NewSDKErrorWithStatus(certs.ErrMalformedEntity, http.StatusBadRequest),
			expected: "",
			domain:   domainID,
			token:    token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			var svcCall *mock.Call
			if tc.desc == "GetEntityID with empty serial" {
				// Empty serial routes to ListCerts endpoint instead of ViewCert
				svcCall = svc.On("ListCerts", mock.Anything, tc.session, mock.Anything).Return(certs.CertificatePage{}, tc.svcerr)
			} else {
				svcCall = svc.On("ViewCert", mock.Anything, tc.session, tc.serial).Return(tc.svcresp, tc.svcerr)
			}

			resp, err := ctsdk.GetEntityID(tc.serial, tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.expected, resp)
			if tc.desc != "GetEntityID with empty serial" {
				ok := svcCall.Parent.AssertCalled(t, "ViewCert", mock.Anything, tc.session, tc.serial)
				assert.True(t, ok)
			}
			svcCall.Unset()
			authCall.Unset()
		})
	}
}

func TestGetCA(t *testing.T) {
	ts, svc, auth := setupCerts()
	defer ts.Close()

	sdkConfig := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	ctsdk := sdk.NewSDK(sdkConfig)

	cases := []struct {
		desc            string
		tokenResp       string
		tokenErr        error
		caResp          certs.Certificate
		caErr           error
		expectedCert    sdk.Certificate
		authenticateErr error
		err             errors.SDKError
		domain          string
		token           string
		session         smqauthn.Session
	}{
		{
			desc:      "GetCA success",
			tokenResp: token,
			tokenErr:  nil,
			caResp: certs.Certificate{
				SerialNumber: serialNum,
				Certificate:  []byte("ca-cert"),
			},
			caErr: nil,
			expectedCert: sdk.Certificate{
				SerialNumber: serialNum,
				Certificate:  "ca-cert",
			},
			err:    nil,
			domain: domainID,
			token:  token,
		},
		{
			desc:         "GetCA token failure",
			tokenResp:    "",
			tokenErr:     certs.ErrGetToken,
			caResp:       certs.Certificate{},
			caErr:        nil,
			expectedCert: sdk.Certificate{},
			err:          errors.NewSDKErrorWithStatus(certs.ErrGetToken, http.StatusUnprocessableEntity),
			domain:       domainID,
			token:        token,
		},
		{
			desc:         "GetCA view CA failure",
			tokenResp:    token,
			tokenErr:     nil,
			caResp:       certs.Certificate{},
			caErr:        certs.ErrViewEntity,
			expectedCert: sdk.Certificate{},
			err:          errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			domain:       domainID,
			token:        token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.token == token {
				tc.session = smqauthn.Session{DomainUserID: id, UserID: id, DomainID: domainID}
			}

			authCall := auth.On("Authenticate", mock.Anything, tc.token).Return(tc.session, tc.authenticateErr)
			tokenCall := svc.On("RetrieveCAToken", mock.Anything, tc.session).Return(tc.tokenResp, tc.tokenErr)
			caCall := svc.On("GetChainCA", mock.Anything, tc.session, tc.tokenResp).Return(tc.caResp, tc.caErr)

			resp, err := ctsdk.GetCA(tc.domain, tc.token)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.expectedCert, resp)

			if tc.desc == "GetCA success" {
				ok := tokenCall.Parent.AssertCalled(t, "RetrieveCAToken", mock.Anything, tc.session)
				assert.True(t, ok)
				ok = caCall.Parent.AssertCalled(t, "GetChainCA", mock.Anything, tc.session, tc.tokenResp)
				assert.True(t, ok)
			} else if tc.desc == "GetCA view CA failure" {
				ok := tokenCall.Parent.AssertCalled(t, "RetrieveCAToken", mock.Anything, tc.session)
				assert.True(t, ok)
				ok = caCall.Parent.AssertCalled(t, "GetChainCA", mock.Anything, tc.session, tc.tokenResp)
				assert.True(t, ok)
			}

			tokenCall.Unset()
			caCall.Unset()
			authCall.Unset()
		})
	}
}

func TestIssueFromCSRInternal(t *testing.T) {
	ts, svc, _ := setupCerts()
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
		desc     string
		entityID string
		ttl      string
		csr      string
		svcresp  certs.Certificate
		svcerr   error
		err      errors.SDKError
		sdkCert  sdk.Certificate
	}{
		{
			desc:     "IssueFromCSRInternal success",
			entityID: validID,
			ttl:      ttl,
			csr:      "valid-csr-content",
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
			desc:     "IssueFromCSRInternal failure",
			entityID: validID,
			ttl:      ttl,
			csr:      "invalid-csr-content",
			svcresp:  certs.Certificate{},
			svcerr:   certs.ErrFailedCertCreation,
			err:      errors.NewSDKErrorWithStatus(certs.ErrFailedCertCreation, http.StatusUnprocessableEntity),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := svc.On("IssueFromCSRInternal", mock.Anything, tc.entityID, tc.ttl, mock.Anything).Return(tc.svcresp, tc.svcerr)

			c, err := ctsdk.IssueFromCSRInternal(tc.entityID, tc.ttl, tc.csr)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.Equal(t, tc.sdkCert.SerialNumber, c.SerialNumber)
				ok := svcCall.Parent.AssertCalled(t, "IssueFromCSRInternal", mock.Anything, tc.entityID, tc.ttl, mock.Anything)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}
