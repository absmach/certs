// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

const serialNumber = "serial number"

var (
	invalidToken = "123"
	config       = certs.Config{
		CommonName: "test",
	}
)

func TestIssueCert(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	testCases := []struct {
		desc      string
		backendId string
		ttl       string
		err       error
		getCAErr  error
	}{
		{
			desc:      "successful issue",
			backendId: "backendId",
			ttl:       "1h",
			err:       nil,
		},
		{
			desc:      "failed repo create cert",
			backendId: "backendId",
			ttl:       "1h",
			err:       certs.ErrCreateEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(tc.err)

			_, err = svc.IssueCert(context.Background(), tc.backendId, tc.ttl, []string{}, certs.SubjectOptions{})
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			repoCall1.Unset()
		})
	}
}

func TestRevokeCert(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	invalidSerialNumber := "invalid serial number"

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	testCases := []struct {
		desc         string
		serial       string
		retrieveErr  error
		err          error
		shouldRevoke bool
	}{
		{
			desc:         "successful revoke",
			serial:       serialNumber,
			err:          nil,
			shouldRevoke: true,
		},
		{
			desc:         "failed repo get cert",
			serial:       invalidSerialNumber,
			retrieveErr:  certs.ErrViewEntity,
			err:          certs.ErrViewEntity,
			shouldRevoke: false,
		},
		{
			desc:         "failed repo update cert",
			serial:       serialNumber,
			err:          certs.ErrUpdateEntity,
			shouldRevoke: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			repoCall1 := cRepo.On("UpdateCert", mock.Anything, mock.Anything).Return(tc.err)
			defer repoCall1.Unset()

			repoCall2 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, tc.retrieveErr)
			defer repoCall2.Unset()

			err = svc.RevokeCert(context.Background(), tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestGetCertDownloadToken(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	testCases := []struct {
		desc   string
		serial string
		err    error
	}{
		{
			desc:   "successful get cert download token",
			serial: serialNumber,
			err:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err = svc.RetrieveCertDownloadToken(context.Background(), tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestGetCert(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5).UTC()), Issuer: certs.Organization, Subject: "certs"})
	validToken, err := jwtToken.SignedString([]byte(serialNumber))
	require.NoError(t, err)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	testCases := []struct {
		desc   string
		token  string
		serial string
		err    error
	}{
		{
			desc:   "successful get cert",
			token:  validToken,
			serial: serialNumber,
			err:    nil,
		},
		{
			desc:   "failed token validation",
			token:  invalidToken,
			serial: serialNumber,
			err:    certs.ErrMalformedEntity,
		},
		{
			desc:   "failed repo get cert",
			token:  validToken,
			serial: serialNumber,
			err:    certs.ErrViewEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, tc.err)
			defer repoCall1.Unset()

			_, _, err = svc.RetrieveCert(context.Background(), tc.token, tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestRenewCert(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	serialNumber := big.NewInt(1)
	expiredSerialNumber := big.NewInt(2)
	revokedSerialNumber := big.NewInt(3)

	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certs.Organization},
			CommonName:   "Test Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour * 24),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}, &x509.Certificate{}, &testKey.PublicKey, testKey)
	require.NoError(t, err)

	expiredCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: expiredSerialNumber,
		Subject: pkix.Name{
			Organization: []string{certs.Organization},
			CommonName:   "Test Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour * 24),
		NotAfter:              time.Now().Add(-time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}, &x509.Certificate{}, &testKey.PublicKey, testKey)
	require.NoError(t, err)

	revokedCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: revokedSerialNumber,
		Subject: pkix.Name{
			Organization: []string{certs.Organization},
			CommonName:   "Test Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour * 24),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}, &x509.Certificate{}, &testKey.PublicKey, testKey)
	require.NoError(t, err)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	testCases := []struct {
		desc        string
		serial      string
		cert        certs.Certificate
		retrieveErr error
		err         error
	}{
		{
			desc:   "successful renew cert",
			serial: serialNumber.String(),
			cert: certs.Certificate{
				SerialNumber: serialNumber.String(),
				Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: validCert}),
				Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
				EntityID:     "backendId",
				ExpiryTime:   time.Now().Add(time.Hour),
				Revoked:      false,
			},
			err: nil,
		},
		{
			desc:        "failed repo get cert",
			serial:      serialNumber.String(),
			cert:        certs.Certificate{},
			retrieveErr: certs.ErrViewEntity,
			err:         certs.ErrViewEntity,
		},
		{
			desc:   "renew expired cert",
			serial: expiredSerialNumber.String(),
			cert: certs.Certificate{
				SerialNumber: expiredSerialNumber.String(),
				Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredCert}),
				Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
				EntityID:     "backendId",
				ExpiryTime:   time.Now().Add(-time.Hour),
				Revoked:      false,
			},
			err: certs.ErrCertExpired,
		},
		{
			desc:   "renew revoked cert",
			serial: revokedSerialNumber.String(),
			cert: certs.Certificate{
				SerialNumber: revokedSerialNumber.String(),
				Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: revokedCert}),
				Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
				EntityID:     "backendId",
				ExpiryTime:   time.Now().Add(time.Hour),
				Revoked:      true,
			},
			err: certs.ErrCertRevoked,
		},
		{
			desc:   "failed repo update cert",
			serial: serialNumber.String(),
			cert: certs.Certificate{
				SerialNumber: serialNumber.String(),
				Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: validCert}),
				Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
				EntityID:     "backendId",
				ExpiryTime:   time.Now().Add(time.Hour),
				Revoked:      false,
			},
			err: certs.ErrUpdateEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(tc.cert, tc.retrieveErr)
			defer repoCall1.Unset()

			repoCall2 := cRepo.On("UpdateCert", mock.Anything, mock.Anything).Return(tc.err)
			defer repoCall2.Unset()

			err = svc.RenewCert(context.Background(), tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestGetEntityID(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	ctx := context.Background()
	serialNumber := "1234567890"
	expectedEntityID := "entity-123"

	t.Run("success", func(t *testing.T) {
		repoCall := cRepo.On("RetrieveCert", ctx, serialNumber).Return(certs.Certificate{EntityID: expectedEntityID}, nil)
		defer repoCall.Unset()
		entityID, err := svc.GetEntityID(ctx, serialNumber)
		assert.NoError(t, err)
		assert.Equal(t, expectedEntityID, entityID)
	})

	t.Run("error retrieving cert", func(t *testing.T) {
		repoCall1 := cRepo.On("RetrieveCert", ctx, serialNumber).Return(certs.Certificate{}, errors.New("not found"))
		defer repoCall1.Unset()
		entityID, err := svc.GetEntityID(ctx, serialNumber)
		assert.Error(t, err)
		assert.Empty(t, entityID)
	})
}

func TestListCerts(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	ctx := context.Background()
	pageMetadata := certs.PageMetadata{Limit: 10, Offset: 0, EntityID: "entity-123"}
	expectedCertPage := certs.CertificatePage{
		Certificates: []certs.Certificate{
			{SerialNumber: "123", EntityID: "entity-123"},
			{SerialNumber: "456", EntityID: "entity-123"},
		},
		PageMetadata: pageMetadata,
	}

	t.Run("success", func(t *testing.T) {
		repoCall := cRepo.On("ListCerts", ctx, pageMetadata).Return(expectedCertPage, nil)
		defer repoCall.Unset()
		certPage, err := svc.ListCerts(ctx, pageMetadata)
		assert.NoError(t, err)
		assert.Equal(t, expectedCertPage, certPage)
	})

	t.Run("error listing certs", func(t *testing.T) {
		repoCall1 := cRepo.On("ListCerts", ctx, pageMetadata).Return(certs.CertificatePage{}, errors.New("database error"))
		defer repoCall1.Unset()
		certPage, err := svc.ListCerts(ctx, pageMetadata)
		assert.Error(t, err)
		assert.Empty(t, certPage)
	})
}

func TestGenerateCRL(t *testing.T) {
	cRepo := new(mocks.MockRepository)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)

	repoCall := cRepo.On("GetCAs", mock.Anything).Return([]certs.Certificate{
		{Type: certs.RootCA, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), Key: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})},
		{Type: certs.IntermediateCA, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), Key: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})},
	}, nil)
	repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
	svc, err := certs.NewService(context.Background(), cRepo, &config)
	require.NoError(t, err)
	repoCall.Unset()
	repoCall1.Unset()

	testCases := []struct {
		desc    string
		caType  certs.CertType
		certs   []certs.Certificate
		repoErr error
		err     error
	}{
		{
			desc:   "generate CRL with root CA",
			caType: certs.RootCA,
			certs: []certs.Certificate{
				{SerialNumber: "1", ExpiryTime: time.Now(), EntityID: "123"},
				{SerialNumber: "2", ExpiryTime: time.Now(), EntityID: "456"},
			},
			err: nil,
		},
		{
			desc:   "generate CRL with intermediate CA",
			caType: certs.IntermediateCA,
			certs: []certs.Certificate{
				{SerialNumber: "3", ExpiryTime: time.Now()},
			},
			err: nil,
		},
		{
			desc:   "invalid CA type",
			caType: certs.CertType(999),
			err:    errors.New("invalid CA type"),
		},
		{
			desc:    "ListRevokedCerts error",
			caType:  certs.RootCA,
			repoErr: certs.ErrViewEntity,
			err:     certs.ErrViewEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			repoCall := cRepo.On("ListRevokedCerts", mock.Anything).Return(tc.certs, tc.repoErr)
			_, err := svc.GenerateCRL(context.Background(), tc.caType)
			if tc.err != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
			repoCall.Unset()
		})
	}
}
