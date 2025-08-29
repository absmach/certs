// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs_test

import (
	"context"
	"testing"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
	"github.com/absmach/certs/mocks"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	serialNumber   = "20:f4:bd:43:2c:c7:06:82:c7:f2:00:47:51:b6:81:6f:fa:c4:46:0c"
	entityID       = "c1a1daea-ce24-4847-b892-1780bf25b10c"
	testCertPEM    = "-----BEGIN CERTIFICATE-----\nMIIEMjCCAxqgAwIBAgIUIPS9QyzHBoLH8gBHUbaBb/rERgwwDQYJKoZIhvcNAQEL\nBQAwgaAxDzANBgNVBAYTBkZSQU5DRTEOMAwGA1UECBMFUEFSSVMxDjAMBgNVBAcT\nBVBBUklTMRowGAYDVQQKExFBYnN0cmFjdCBNYWNoaW5lczEaMBgGA1UECxMRQWJz\ndHJhY3QgTWFjaGluZXMxNTAzBgNVBAMTLEFic3RyYWN0IE1hY2hpbmVzIFJvb3Qg\nQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTI1MDgyNTExNTAyNFoXDTI1MDgyNTIx\nNTA1NFowDzENMAsGA1UEAxMEMDAwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMT4eHWFYUVAmQWC0bcgcBuBQjDVWdXD2WJWx8ybeC8vIwsGyCRMEem4\nlveP937ZjM3TTX0Nst4chF0L3WN0FTGTztwlqtpCK67AxcMEdGj54kIlVMAZexLz\nY4mQ5Oe/S4L4elv/ARHDV87BZ0m7oD1b2AC+8CBdm9aWcaD1RZk6qtzLRjs17ouY\nuslj5dN33VuzTYYUlPaTFjCY2nnebK0FLNjJkBVjoIlmT1Oo56uw9SQpLczk4PtL\nlVzeNKHGh0mx3g13tyNOAjKrMvxb7GTQ3tKsL6zZfiWggw4gROqjGQuCejAibfrr\nftN77YndLF4JYqiUZRCsZlRMSkpcSWMCAwEAAaOB8zCB8DAOBgNVHQ8BAf8EBAMC\nA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSEDX9D\nU9O6ORjZOJzceZmE2yC93DAfBgNVHSMEGDAWgBSZCSNs3yScbg5YSiuN1VuS6o3g\nyTA7BggrBgEFBQcBAQQvMC0wKwYIKwYBBQUHMAKGH2h0dHA6Ly8xMjcuMC4wLjE6\nODIwMC92MS9wa2kvY2EwDwYDVR0RBAgwBocEwKhkFDAxBgNVHR8EKjAoMCagJKAi\nhiBodHRwOi8vMTI3LjAuMC4xOjgyMDAvdjEvcGtpL2NybDANBgkqhkiG9w0BAQsF\nAAOCAQEAK5fOOweOOJzWmjC0/6A9T/xnTOeXcwdp3gBmMNkaCs/qlh+3Dofo9vHS\nX1vitXbcqbMmJnXuRLkA+qTTlJvhVD8fa4RtixJZ5N0uDMPJ5FVv9tipSoqcnQH8\nwR4iPvrlQQr5hiBt/nfsaTLuDLZgMcKs5N30yHslJXfeLcWrawaQHpIddgavbgqM\n/9L/PoWM2hJknUyg7kis5SNejUGwOh/U1MUf1b18kaUKeK3Q4vhVHVz4foiRZ9M0\niw9xTj2rJJdOE/omE6qJFIfWIF0DuOCYt7z8TKhqKuTfNjmmiqlcgT14P6hniFkK\nl/5upJw86TWS8J0RXQJ1Nbw68EMEuQ==\n-----END CERTIFICATE-----"
	testCAChainPEM = "-----BEGIN CERTIFICATE-----\nMIIEMjCCAxqgAwIBAgIUIPS9QyzHBoLH8gBHUbaBb/rERgwwDQYJKoZIhvcNAQEL\nBQAwgaAxDzANBgNVBAYTBkZSQU5DRTEOMAwGA1UECBMFUEFSSVMxDjAMBgNVBAcT\nBVBBUklTMRowGAYDVQQKExFBYnN0cmFjdCBNYWNoaW5lczEaMBgGA1UECxMRQWJz\ndHJhY3QgTWFjaGluZXMxNTAzBgNVBAMTLEFic3RyYWN0IE1hY2hpbmVzIFJvb3Qg\nQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTI1MDgyNTExNTAyNFoXDTI1MDgyNTIx\nNTA1NFowDzENMAsGA1UEAxMEMDAwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMT4eHWFYUVAmQWC0bcgcBuBQjDVWdXD2WJWx8ybeC8vIwsGyCRMEem4\nlveP937ZjM3TTX0Nst4chF0L3WN0FTGTztwlqtpCK67AxcMEdGj54kIlVMAZexLz\nY4mQ5Oe/S4L4elv/ARHDV87BZ0m7oD1b2AC+8CBdm9aWcaD1RZk6qtzLRjs17ouY\nuslj5dN33VuzTYYUlPaTFjCY2nnebK0FLNjJkBVjoIlmT1Oo56uw9SQpLczk4PtL\nlVzeNKHGh0mx3g13tyNOAjKrMvxb7GTQ3tKsL6zZfiWggw4gROqjGQuCejAibfrr\nftN77YndLF4JYqiUZRCsZlRMSkpcSWMCAwEAAaOB8zCB8DAOBgNVHQ8BAf8EBAMC\nA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSEDX9D\nU9O6ORjZOJzceZmE2yC93DAfBgNVHSMEGDAWgBSZCSNs3yScbg5YSiuN1VuS6o3g\nyTA7BggrBgEFBQcBAQQvMC0wKwYIKwYBBQUHMAKGH2h0dHA6Ly8xMjcuMC4wLjE6\nODIwMC92MS9wa2kvY2EwDwYDVR0RBAgwBocEwKhkFDAxBgNVHR8EKjAoMCagJKAi\nhiBodHRwOi8vMTI3LjAuMC4xOjgyMDAvdjEvcGtpL2NybDANBgkqhkiG9w0BAQsF\nAAOCAQEAK5fOOweOOJzWmjC0/6A9T/xnTOeXcwdp3gBmMNkaCs/qlh+3Dofo9vHS\nX1vitXbcqbMmJnXuRLkA+qTTlJvhVD8fa4RtixJZ5N0uDMPJ5FVv9tipSoqcnQH8\nwR4iPvrlQQr5hiBt/nfsaTLuDLZgMcKs5N30yHslJXfeLcWrawaQHpIddgavbgqM\n/9L/PoWM2hJknUyg7kis5SNejUGwOh/U1MUf1b18kaUKeK3Q4vhVHVz4foiRZ9M0\niw9xTj2rJJdOE/omE6qJFIfWIF0DuOCYt7z8TKhqKuTfNjmmiqlcgT14P6hniFkK\nl/5upJw86TWS8J0RXQJ1Nbw68EMEuQ==\n-----END CERTIFICATE-----"
)

var (
	invalidToken       = "123"
	certValidityPeriod = time.Hour * 24 * 30
)

func TestIssueCert(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	testCases := []struct {
		desc     string
		entityID string
		ttl      string
		cert     certs.Certificate
		err      error
		agentErr error
	}{
		{
			desc:     "issue cert successfully",
			entityID: "entityID",
			ttl:      "1h",
			cert: certs.Certificate{
				SerialNumber: serialNumber,
				EntityID:     "entityID",
			},
			err: nil,
		},
		{
			desc:     "failed agent issue cert",
			entityID: "entityID",
			ttl:      "1h",
			cert:     certs.Certificate{},
			agentErr: errors.New("agent error"),
			err:      certs.ErrFailedCertCreation,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("Issue", tc.entityID, tc.ttl, []string{}, certs.SubjectOptions{}).Return(tc.cert, tc.agentErr)

			cert, err := svc.IssueCert(context.Background(), tc.entityID, "thing", tc.ttl, []string{}, certs.SubjectOptions{})
			if tc.err != nil {
				require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.cert, cert)
			}

			agentCall.Unset()
		})
	}
}

func TestRevokeBySerial(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	testCases := []struct {
		desc     string
		serial   string
		agentErr error
		err      error
	}{
		{
			desc:   "revoke cert by serial successfully",
			serial: serialNumber,
			err:    nil,
		},
		{
			desc:     "failed agent revoke",
			serial:   serialNumber,
			agentErr: errors.New("agent error"),
			err:      certs.ErrUpdateEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("Revoke", tc.serial).Return(tc.agentErr)

			err = svc.RevokeBySerial(context.Background(), tc.serial)
			if tc.err != nil {
				require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			} else {
				require.NoError(t, err)
			}

			agentCall.Unset()
		})
	}
}

func TestGetCertDownloadToken(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	testCases := []struct {
		desc   string
		serial string
		token  string
		err    error
	}{
		{
			desc:   "get cert download token successfully",
			serial: serialNumber,
			token:  "valid_token",
			err:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			token, err := svc.RetrieveCertDownloadToken(context.Background(), tc.serial)
			if tc.err != nil {
				require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, token)
			}
		})
	}
}

func TestGetCert(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5).UTC()), Issuer: certs.Organization, Subject: "certs"})
	validToken, err := jwtToken.SignedString([]byte(serialNumber))
	require.NoError(t, err)

	testCert := certs.Certificate{
		SerialNumber: serialNumber,
		EntityID:     "test-entity",
		Certificate:  []byte(testCertPEM),
	}

	caChain := []byte(testCAChainPEM)

	testCases := []struct {
		desc       string
		token      string
		serial     string
		cert       certs.Certificate
		caChain    []byte
		viewErr    error
		caChainErr error
		err        error
	}{
		{
			desc:    "retrieve cert successfully",
			token:   validToken,
			serial:  serialNumber,
			cert:    testCert,
			caChain: caChain,
			err:     nil,
		},
		{
			desc:   "failed token validation",
			token:  invalidToken,
			serial: serialNumber,
			cert:   certs.Certificate{},
			err:    certs.ErrMalformedEntity,
		},
		{
			desc:    "failed agent view cert",
			token:   validToken,
			serial:  serialNumber,
			cert:    certs.Certificate{},
			viewErr: errors.New("agent error"),
			err:     certs.ErrViewEntity,
		},
		{
			desc:       "failed agent get ca chain",
			token:      validToken,
			serial:     serialNumber,
			cert:       testCert,
			caChain:    []byte{},
			caChainErr: errors.New("ca chain error"),
			err:        certs.ErrViewEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("View", tc.serial).Return(tc.cert, tc.viewErr)
			agentCall1 := agent.On("GetCAChain").Return(tc.caChain, tc.caChainErr)

			_, _, err := svc.RetrieveCert(context.Background(), tc.token, tc.serial)
			if tc.err != nil {
				require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			} else {
				require.NoError(t, err)
			}

			agentCall.Unset()
			agentCall1.Unset()
		})
	}
}

func TestRenewCert(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	newCert := certs.Certificate{
		SerialNumber: serialNumber,
		EntityID:     entityID,
		Certificate:  []byte(testCertPEM),
		ExpiryTime:   time.Now().Add(30 * 24 * time.Hour),
	}

	testCases := []struct {
		desc        string
		serial      string
		viewErr     error
		renewErr    error
		newCert     certs.Certificate
		revoked     bool
		expectedErr error
	}{
		{
			desc:        "renew cert successfully",
			serial:      serialNumber,
			newCert:     newCert,
			expectedErr: nil,
		},
		{
			desc:        "failed agent renew",
			serial:      serialNumber,
			renewErr:    certs.ErrUpdateEntity,
			newCert:     certs.Certificate{},
			expectedErr: certs.ErrUpdateEntity,
		},
		{
			desc:        "failed agent view",
			serial:      serialNumber,
			viewErr:     certs.ErrViewEntity,
			newCert:     certs.Certificate{},
			expectedErr: certs.ErrViewEntity,
		},
		{
			desc:        "revoked certificate cannot be renewed",
			serial:      serialNumber,
			newCert:     certs.Certificate{},
			revoked:     true,
			expectedErr: certs.ErrCertRevoked,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("Renew", mock.Anything, certValidityPeriod.String()).Return(tc.newCert, tc.renewErr)
			agentCall1 := agent.On("View", tc.serial).Return(certs.Certificate{Certificate: []byte(testCertPEM), Revoked: tc.revoked}, tc.viewErr)

			renewedCert, err := svc.RenewCert(context.Background(), tc.serial)
			require.True(t, errors.Contains(err, tc.expectedErr), "expected error %v, got %v", tc.expectedErr, err)
			if tc.expectedErr == nil {
				require.Equal(t, tc.newCert, renewedCert)
			}
			agentCall1.Unset()
			agentCall.Unset()
		})
	}
}

func TestGetEntityID(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	testCases := []struct {
		desc     string
		serial   string
		cert     certs.Certificate
		agentErr error
		err      error
	}{
		{
			desc:   "get entity ID successfully",
			serial: serialNumber,
			cert:   certs.Certificate{EntityID: "entity-123"},
			err:    nil,
		},
		{
			desc:     "error retrieving cert",
			serial:   serialNumber,
			cert:     certs.Certificate{},
			agentErr: errors.New("not found"),
			err:      certs.ErrViewEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("View", tc.serial).Return(tc.cert, tc.agentErr)

			entityID, err := svc.GetEntityID(context.Background(), tc.serial)
			if tc.err != nil {
				require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
				require.Empty(t, entityID)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.cert.EntityID, entityID)
			}

			agentCall.Unset()
		})
	}
}

func TestListCerts(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	pageMetadata := certs.PageMetadata{Limit: 10, Offset: 0, EntityID: "entity-123"}
	expectedCertPage := certs.CertificatePage{
		Certificates: []certs.Certificate{
			{SerialNumber: "123", EntityID: "entity-123"},
			{SerialNumber: "456", EntityID: "entity-123"},
		},
		PageMetadata: pageMetadata,
	}

	testCases := []struct {
		desc     string
		pm       certs.PageMetadata
		certPage certs.CertificatePage
		agentErr error
		err      error
	}{
		{
			desc:     "list certs successfully",
			pm:       pageMetadata,
			certPage: expectedCertPage,
			err:      nil,
		},
		{
			desc:     "error listing certs",
			pm:       pageMetadata,
			certPage: certs.CertificatePage{},
			agentErr: errors.New("agent error"),
			err:      certs.ErrViewEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("ListCerts", tc.pm).Return(tc.certPage, tc.agentErr)

			certPage, err := svc.ListCerts(context.Background(), tc.pm)
			if tc.err != nil {
				require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
				require.Empty(t, certPage)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.certPage, certPage)
			}

			agentCall.Unset()
		})
	}
}

func TestGenerateCRL(t *testing.T) {
	agent := new(mocks.Agent)
	svc, err := certs.NewService(context.Background(), agent)
	require.NoError(t, err)

	testCases := []struct {
		desc     string
		caType   certs.CertType
		crlBytes []byte
		agentErr error
		err      error
	}{
		{
			desc:     "generate CRL with root CA",
			caType:   certs.RootCA,
			crlBytes: []byte("test-crl-data"),
			err:      nil,
		},
		{
			desc:     "generate CRL with intermediate CA",
			caType:   certs.IntermediateCA,
			crlBytes: []byte("test-crl-data"),
			err:      nil,
		},
		{
			desc:     "failed with agent error",
			caType:   certs.RootCA,
			crlBytes: nil,
			agentErr: errors.New("agent error"),
			err:      certs.ErrFailedCertCreation,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			agentCall := agent.On("GetCRL").Return(tc.crlBytes, tc.agentErr)

			crlBytes, err := svc.GenerateCRL(context.Background(), tc.caType)
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.crlBytes, crlBytes)
			}

			agentCall.Unset()
		})
	}
}
