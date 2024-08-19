// Copyright (c) Ultraviolet
package postgres

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/pkg/errors"
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

	// nonExistentEntityID, err := idProvider.ID()
	// require.NoError(t, err)

	serialNumber := big.NewInt(25)
	serialNumber2 := big.NewInt(26)

	testCases := []struct {
		desc string
		cert        certs.Certificate
		err         error
	}{
		{
			desc: "successful save",
			cert:        certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()},
			err:         nil,
		},
		{
			desc: "save with violating foreign key",
			cert:        certs.Certificate{SerialNumber: serialNumber2.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: id, Revoked: false, ExpiryDate: time.Now()},
			err:         service.ErrConflict,
		},
		{
			desc: "save with invalid backend id",
			cert:        certs.Certificate{SerialNumber: serialNumber.String(), Certificate: []byte("cert"), Key: []byte("key"), EntityID: "invalid", Revoked: false, ExpiryDate: time.Now()},
			err:         service.ErrConflict,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
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
		desc string
		id          string
		err         error
	}{
		{
			desc: "successful view",
			id:          serialNumber.String(),
			err:         nil,
		},
		{
			desc: "view with invalid id",
			id:          invalidId,
			err:         service.ErrNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
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
		desc string
		userId      string
		limit       uint64
		offset      uint64
		total       int
		err         error
	}{
		{
			desc: "successful list",
			limit:       10,
			offset:      0,
			total:       10,
			err:         nil,
		},
		{
			desc: "offset 20",
			limit:       10,
			offset:      20,
			total:       5,
			err:         nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := repo.ListCerts(context.Background(),tc.userId, certs.PageMetadata{Limit: tc.limit, Offset: tc.offset})
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}
