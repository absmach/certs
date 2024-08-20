// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/absmach/certs"
	"github.com/absmach/certs/internal/postgres"
	"github.com/absmach/certs/pkg/errors"
	"github.com/absmach/certs/pkg/errors/service"
	"github.com/jackc/pgx/v5/pgconn"
)

// Postgres error codes:
// https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	errDuplicate      = "23505" // unique_violation
	errTruncation     = "22001" // string_data_right_truncation
	errFK             = "23503" // foreign_key_violation
	errInvalid        = "22P02" // invalid_text_representation
	errUntranslatable = "22P05" // untranslatable_character
	errInvalidChar    = "22021" // character_not_in_repertoire
)

var (
	ErrConflict        = errors.New("entity already exists")
	ErrMalformedEntity = errors.New("malformed entity")
	ErrCreateEntity    = errors.New("failed to create entity")
)

type certsRepo struct {
	db postgres.Database
}

func NewRepository(db postgres.Database) certs.Repository {
	return certsRepo{
		db: db,
	}
}

// CreateLog creates computation log in the database.
func (repo certsRepo) CreateCert(ctx context.Context, cert certs.Certificate) error {
	q := `
	INSERT INTO certs (serial_number, certificate, key, entity_id, entity_type, revoked, expiry_date, created_by, created_at)
	VALUES (:serial_number, :certificate, :key, :entity_id, :entity_type, :revoked, :expiry_date, :created_by, :created_at)`
	_, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return handleError(service.ErrCreateEntity, err)
	}
	return nil
}

// RetrieveLog retrieves computation log from the database.
func (repo certsRepo) RetrieveCert(ctx context.Context, serialNumber string) (certs.Certificate, error) {
	q := `SELECT * FROM certs WHERE serial_number = $1`
	var cert certs.Certificate
	if err := repo.db.QueryRowxContext(ctx, q, serialNumber).StructScan(&cert); err != nil {
		if err == sql.ErrNoRows {
			return certs.Certificate{}, errors.Wrap(service.ErrNotFound, err)
		}
		return certs.Certificate{}, errors.Wrap(service.ErrViewEntity, err)
	}
	return cert, nil
}

// UpdateLog updates computation log in the database.
func (repo certsRepo) UpdateCert(ctx context.Context, cert certs.Certificate) error {
	q := `UPDATE certs SET certificate = :certificate, key = :key, revoked = :revoked, expiry_date = :expiry_date, updated_by = :updated_by, updated_at = :updated_at WHERE serial_number = :serial_number`
	res, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return handleError(service.ErrUpdateEntity, err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(service.ErrUpdateEntity, err)
	}
	if count == 0 {
		return service.ErrNotFound
	}
	return nil
}

func (repo certsRepo) ListCerts(ctx context.Context, userId string, pm certs.PageMetadata) (certs.CertificatePage, error) {
	q := `SELECT serial_number, revoked, expiry_date, entity_id FROM certs %s LIMIT :limit OFFSET :offset`
	condition := ``
	if pm.EntityID != "" {
		condition = `WHERE entity_id = :entity_id AND created_by = :created_by`
		q = fmt.Sprintf(q, condition)
	} else {
		q = fmt.Sprintf(q, condition)
	}
	var certificates []certs.Certificate

	params := map[string]interface{}{
		"limit":      pm.Limit,
		"offset":     pm.Offset,
		"entity_id":  pm.EntityID,
		"created_by": userId,
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return certs.CertificatePage{}, handleError(service.ErrViewEntity, err)
	}
	defer rows.Close()

	for rows.Next() {
		cert := &certs.Certificate{}
		if err := rows.StructScan(cert); err != nil {
			return certs.CertificatePage{}, errors.Wrap(service.ErrViewEntity, err)
		}

		certificates = append(certificates, *cert)
	}

	q = fmt.Sprintf(`SELECT COUNT(*) FROM certs %s LIMIT :limit OFFSET :offset`, condition)
	pm.Total, err = repo.total(ctx, q, params)
	if err != nil {
		return certs.CertificatePage{}, errors.Wrap(service.ErrViewEntity, err)
	}
	return certs.CertificatePage{
		PageMetadata: pm,
		Certificates: certificates,
	}, nil
}

func (repo certsRepo) total(ctx context.Context, query string, params interface{}) (uint64, error) {
	rows, err := repo.db.NamedQueryContext(ctx, query, params)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	total := uint64(0)
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func handleError(wrapper, err error) error {
	pqErr, ok := err.(*pgconn.PgError)
	if ok {
		switch pqErr.Code {
		case errDuplicate:
			return errors.Wrap(ErrConflict, err)
		case errInvalid, errInvalidChar, errTruncation, errUntranslatable:
			return errors.Wrap(ErrMalformedEntity, err)
		case errFK:
			return errors.Wrap(ErrCreateEntity, err)
		}
	}

	return errors.Wrap(wrapper, err)
}
