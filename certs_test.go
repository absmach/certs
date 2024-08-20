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
	"os"
	"testing"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/mocks"
	"github.com/absmach/certs/pkg/errors"
	"github.com/absmach/certs/pkg/errors/service"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const serialNumber = "serial number"

var (
	user         = "userid"
	invalidToken = "123"
)

func TestIssueCert(t *testing.T) {
	cRepo := new(mocks.Repository)

	rootCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCACert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{certs.Organization},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, &x509.Certificate{}, &rootCAKey.PublicKey, rootCAKey)
	require.NoError(t, err)

	caCertFile, err := os.CreateTemp("", "rootCA.crt")
	require.NoError(t, err)

	err = pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCACert})
	require.NoError(t, err)

	caKeyFile, err := os.CreateTemp("", "rootCA.key")
	require.NoError(t, err)
	marsheledKey, err := x509.MarshalPKCS8PrivateKey(rootCAKey)
	require.NoError(t, err)
	err = pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: marsheledKey})
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(caCertFile.Name())
		os.Remove(caKeyFile.Name())
	})

	listCall := cRepo.On("ListCerts", mock.Anything, mock.Anything).Return(certs.CertificatePage{}, nil)
	t.Cleanup(func() {
		listCall.Unset()
	})

	svcNoCert, err := certs.NewService(context.Background(), cRepo, "", "")
	require.NoError(t, err)

	svc, err := certs.NewService(context.Background(), cRepo, caCertFile.Name(), caKeyFile.Name())
	require.NoError(t, err)

	testCases := []struct {
		desc      string
		userId    string
		backendId string
		err       error
	}{
		{
			desc:      "successful issue",
			userId:    user,
			backendId: "backendId",
			err:       nil,
		},
		{
			desc:      "missing root CA",
			backendId: "backendId",
			err:       service.ErrRootCANotFound,
		},
		{
			desc:      "failed repo create cert",
			backendId: "backendId",
			err:       service.ErrCreateEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.err == service.ErrCreateEntity {
				repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(tc.err)
				defer repoCall1.Unset()
			} else {
				repoCall1 := cRepo.On("CreateCert", mock.Anything, mock.Anything).Return(nil)
				defer repoCall1.Unset()
			}

			_, err = svc.IssueCert(context.Background(), tc.userId, tc.backendId, certs.EntityTypeBackend, []string{})
			if tc.desc == "missing root CA" {
				_, err = svcNoCert.IssueCert(context.Background(), tc.userId, tc.backendId, certs.EntityTypeBackend, []string{})
			}

			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestRevokeCert(t *testing.T) {
	cRepo := new(mocks.Repository)

	invalidSerialNumber := "invalid serial number"

	listCall := cRepo.On("ListCerts", mock.Anything, mock.Anything, mock.Anything).Return(certs.CertificatePage{}, nil)
	t.Cleanup(func() {
		listCall.Unset()
	})

	svc, err := certs.NewService(context.Background(), cRepo, "", "")
	require.NoError(t, err)

	testCases := []struct {
		desc         string
		userId       string
		serial       string
		err          error
		shouldRevoke bool
	}{
		{
			desc:         "successful revoke",
			userId:       user,
			serial:       serialNumber,
			err:          nil,
			shouldRevoke: true,
		},
		{
			desc:         "failed repo get cert",
			userId:       user,
			serial:       invalidSerialNumber,
			err:          service.ErrViewEntity,
			shouldRevoke: false,
		},
		{
			desc:         "failed repo update cert",
			userId:       user,
			serial:       serialNumber,
			err:          service.ErrUpdateEntity,
			shouldRevoke: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.shouldRevoke {
				repoCall1 := cRepo.On("UpdateCert", mock.Anything, mock.Anything).Return(nil)
				defer repoCall1.Unset()
			} else {
				repoCall1 := cRepo.On("UpdateCert", mock.Anything, mock.Anything).Return(service.ErrUpdateEntity)
				defer repoCall1.Unset()
			}

			switch tc.serial {
			case serialNumber:
				repoCall2 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, nil)
				defer repoCall2.Unset()
			case invalidSerialNumber:
				repoCall2 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, service.ErrViewEntity)
				defer repoCall2.Unset()
			}

			err = svc.RevokeCert(context.Background(), tc.userId, tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestGetCertDownloadToken(t *testing.T) {
	cRepo := new(mocks.Repository)

	listCall := cRepo.On("ListCerts", mock.Anything, mock.Anything).Return(certs.CertificatePage{}, nil)
	t.Cleanup(func() {
		listCall.Unset()
	})

	svc, err := certs.NewService(context.Background(), cRepo, "", "")
	require.NoError(t, err)

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
	cRepo := new(mocks.Repository)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Minute * 5).Unix(), Issuer: certs.Organization, Subject: "certs"})
	validToken, err := jwtToken.SignedString([]byte(serialNumber))
	require.NoError(t, err)

	rootCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCACert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{certs.Organization},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, &x509.Certificate{}, &rootCAKey.PublicKey, rootCAKey)
	require.NoError(t, err)

	caCertFile, err := os.CreateTemp("", "rootCA.crt")
	require.NoError(t, err)

	err = pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCACert})
	require.NoError(t, err)

	caKeyFile, err := os.CreateTemp("", "rootCA.key")
	require.NoError(t, err)
	marsheledKey, err := x509.MarshalPKCS8PrivateKey(rootCAKey)
	require.NoError(t, err)
	err = pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: marsheledKey})
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(caCertFile.Name())
		os.Remove(caKeyFile.Name())
	})

	listCall := cRepo.On("ListCerts", mock.Anything, mock.Anything).Return(certs.CertificatePage{}, nil)
	t.Cleanup(func() {
		listCall.Unset()
	})

	svc, err := certs.NewService(context.Background(), cRepo, caCertFile.Name(), caKeyFile.Name())
	require.NoError(t, err)

	testCases := []struct {
		desc   string
		token  string
		userId string
		serial string
		err    error
	}{
		{
			desc:   "successful get cert",
			token: validToken,
			userId: user,
			serial: serialNumber,
			err:    nil,
		},
		{
			desc: "failed token validation",
			token: invalidToken,
			userId: user,
			serial: serialNumber,
			err:    service.ErrMalformedEntity,
		},
		{
			desc:   "failed repo get cert",
			token: validToken,
			userId: user,
			serial: serialNumber,
			err:    service.ErrViewEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.err == service.ErrViewEntity {
				repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, tc.err)
				defer repoCall1.Unset()
			} else {
				repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, nil)
				defer repoCall1.Unset()
			}

			_, _, err = svc.RetrieveCert(context.Background(), tc.token, tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func TestRenewCert(t *testing.T) {
	cRepo := new(mocks.Repository)

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

	rootCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCACert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{certs.Organization},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, &x509.Certificate{}, &rootCAKey.PublicKey, rootCAKey)
	require.NoError(t, err)

	caCertFile, err := os.CreateTemp("", "rootCA.crt")
	require.NoError(t, err)

	err = pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCACert})
	require.NoError(t, err)

	caKeyFile, err := os.CreateTemp("", "rootCA.key")
	require.NoError(t, err)
	marsheledKey, err := x509.MarshalPKCS8PrivateKey(rootCAKey)
	require.NoError(t, err)
	err = pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: marsheledKey})
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(caCertFile.Name())
		os.Remove(caKeyFile.Name())
	})

	listCall := cRepo.On("ListCerts", mock.Anything, mock.Anything).Return(certs.CertificatePage{}, nil)
	t.Cleanup(func() {
		listCall.Unset()
	})

	svc, err := certs.NewService(context.Background(), cRepo, caCertFile.Name(), caKeyFile.Name())
	require.NoError(t, err)

	testCases := []struct {
		desc   string
		userId string
		serial string
		err    error
	}{
		{
			desc:   "successful renew cert",
			userId: user,
			serial: serialNumber.String(),
			err:    nil,
		},
		{
			desc:   "failed repo get cert",
			userId: user,
			serial: serialNumber.String(),
			err:    service.ErrViewEntity,
		},
		{
			desc:   "renew expired cert",
			userId: user,
			serial: expiredSerialNumber.String(),
			err:    service.ErrCertExpired,
		},
		{
			desc:   "renew revoked cert",
			userId: user,
			serial: revokedSerialNumber.String(),
			err:    service.ErrCertRevoked,
		},
		{
			desc:   "failed repo update cert",
			userId: user,
			serial: serialNumber.String(),
			err:    service.ErrUpdateEntity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.err == service.ErrViewEntity {
				repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{}, tc.err)
				defer repoCall1.Unset()
			} else {
				switch tc.serial {
				case serialNumber.String():
					repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{
						SerialNumber: serialNumber.String(),
						Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: validCert}),
						Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
						EntityID:     "backendId",
						ExpiryDate:   time.Now().Add(time.Hour),
						Revoked:      false,
					}, nil)
					defer repoCall1.Unset()
				case expiredSerialNumber.String():
					repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{
						SerialNumber: expiredSerialNumber.String(),
						Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredCert}),
						Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
						EntityID:     "backendId",
						ExpiryDate:   time.Now().Add(-time.Hour),
						Revoked:      false,
					}, nil)
					defer repoCall1.Unset()
				case revokedSerialNumber.String():
					repoCall1 := cRepo.On("RetrieveCert", mock.Anything, mock.Anything).Return(certs.Certificate{
						SerialNumber: revokedSerialNumber.String(),
						Certificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: revokedCert}),
						Key:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}),
						EntityID:     "backendId",
						ExpiryDate:   time.Now().Add(time.Hour),
						Revoked:      true,
					}, nil)
					defer repoCall1.Unset()
				}
			}

			if tc.err == service.ErrUpdateEntity {
				repoCall2 := cRepo.On("UpdateCert", mock.Anything, mock.Anything).Return(service.ErrUpdateEntity)
				defer repoCall2.Unset()
			} else {
				repoCall2 := cRepo.On("UpdateCert", mock.Anything, mock.Anything).Return(nil)
				defer repoCall2.Unset()
			}

			err = svc.RenewCert(context.Background(), tc.userId, tc.serial)
			require.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}
