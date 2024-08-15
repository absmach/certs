// Copyright (c) Ultraviolet
package postgres

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/ulid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var idProvider = ulid.New()

func TestCreateCert(t *testing.T) {
	repo := NewRepository(db)

	id, err := idProvider.ID()
	require.NoError(t, err)

	serialNumber := big.NewInt(25)
	serialNumber2 := big.NewInt(26)

	testCases := []struct {
		description string
		cert        certs.Certificate
		err         error
	}{
		{
			description: "successful save",
			cert:        certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()},
			err:         nil,
		},
		{
			description: "save with violating foreign key",
			cert:        certs.Certificate{SerialNumber: serialNumber2.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()},
			err:         service.ErrConflict,
		},
		{
			description: "save with invalid backend id",
			cert:        certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: "invalid", Revoked: false, ExpiryDate: time.Now()},
			err:         service.ErrConflict,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			if tc.description == "save with violating foreign key" {
				err := repo.CreateCert(context.Background(), certs.Certificate{SerialNumber: serialNumber2.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()})
				assert.NoError(t, err)
			}

			err := repo.CreateCert(context.Background(), tc.cert)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestGetCert(t *testing.T) {
	repo := NewRepository(db)

	id, err := idProvider.ID()
	require.NoError(t, err)
	invalidId, err := idProvider.ID()
	require.NoError(t, err)

	serialNumber := big.NewInt(24)

	err = repo.CreateCert(context.Background(), certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()})
	require.NoError(t, err)

	testCases := []struct {
		description string
		id          string
		err         error
	}{
		{
			description: "successful view",
			id:          serialNumber.String(),
			err:         nil,
		},
		{
			description: "view with invalid id",
			id:          invalidId,
			err:         service.ErrNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			_, err := repo.RetrieveCert(context.Background(), tc.id)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestUpdateCert(t *testing.T) {
	repo := NewRepository(db)

	id, err := idProvider.ID()
	require.NoError(t, err)
	invalidId, err := idProvider.ID()
	require.NoError(t, err)

	serialNumber := big.NewInt(23)

	err = repo.CreateCert(context.Background(), certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()})
	require.NoError(t, err)

	testCases := []struct {
		description string
		cert        certs.Certificate
		err         error
	}{
		{
			description: "successful update",
			cert:        certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: true, ExpiryDate: time.Now()},
			err:         nil,
		},
		{
			description: "update with invalid id",
			cert:        certs.Certificate{SerialNumber: invalidId, Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: true, ExpiryDate: time.Now()},
			err:         service.ErrNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := repo.UpdateCert(context.Background(), tc.cert)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestListCerts(t *testing.T) {
	repo := NewRepository(db)

	id, err := idProvider.ID()
	require.NoError(t, err)

	for i := 1; i < 22; i++ {
		serialNumber := big.NewInt(int64(i))

		err := repo.CreateCert(context.Background(), certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()})
		require.NoError(t, err)
	}

	testCases := []struct {
		description string
		limit       uint64
		offset      uint64
		total       int
		err         error
	}{
		{
			description: "successful list",
			limit:       10,
			offset:      0,
			total:       10,
			err:         nil,
		},
		{
			description: "offset 20",
			limit:       10,
			offset:      20,
			total:       5,
			err:         nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			_, err := repo.ListCerts(context.Background(), certs.PageMetadata{Limit: tc.limit, Offset: tc.offset})
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}
