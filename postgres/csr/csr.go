// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
	"github.com/absmach/certs/internal/postgres"
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

type CSRRepo struct {
	db postgres.Database
}

func NewRepository(db postgres.Database) certs.CSRRepository {
	return CSRRepo{
		db: db,
	}
}

func (repo CSRRepo) CreateCSR(ctx context.Context, cert certs.CSR) error {
	q := `
	INSERT INTO certs (id, serial_number, csr, private_key, entity_id, status, submitted_at, processed_at)
	VALUES (:id, :serial_number, :csr, :private_key, :entity_id, :status, :submitted_at, :processed_at)`
	_, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return handleError(certs.ErrCreateEntity, err)
	}
	return nil
}

func (repo CSRRepo) UpdateCSR(ctx context.Context, cert certs.CSR) error {
	q := `UPDATE certs SET certificate = :certificate, key = :key, revoked = :revoked, expiry_time = :expiry_time WHERE serial_number = :serial_number`
	res, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return handleError(certs.ErrUpdateEntity, err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(certs.ErrUpdateEntity, err)
	}
	if count == 0 {
		return certs.ErrNotFound
	}
	return nil
}

func (repo CSRRepo) RetrieveCSR(ctx context.Context,id string) (certs.CSR, error) {
	q := `SELECT serial_number, certificate, key, entity_id, revoked, expiry_time FROM certs WHERE id = $1`
	var csr certs.CSR
	if err := repo.db.QueryRowxContext(ctx, q, id).StructScan(&csr); err != nil {
		if err == sql.ErrNoRows {
			return certs.CSR{}, errors.Wrap(certs.ErrNotFound, err)
		}
		return certs.CSR{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	return csr, nil
}

func (repo CSRRepo) ListCSRs(ctx context.Context, pm certs.PageMetadata) (certs.CSRPage, error) {
	q := `SELECT serial_number, status, submitted_at, processed_at, entity_id FROM certs %s LIMIT :limit OFFSET :offset`
	var condition string
	if pm.EntityID != "" {
		condition = `WHERE entity_id = :entity_id`
	} else {
		condition = ``
	}
	q = fmt.Sprintf(q, condition)
	var csrs []certs.CSR

	params := map[string]interface{}{
		"limit":     pm.Limit,
		"offset":    pm.Offset,
		"entity_id": pm.EntityID,
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return certs.CSRPage{}, handleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	for rows.Next() {
		csr := &certs.CSR{}
		if err := rows.StructScan(csr); err != nil {
			return certs.CSRPage{}, errors.Wrap(certs.ErrViewEntity, err)
		}

		csrs = append(csrs, *csr)
	}

	q = fmt.Sprintf(`SELECT COUNT(*) FROM certs %s LIMIT :limit OFFSET :offset`, condition)
	pm.Total, err = repo.total(ctx, q, params)
	if err != nil {
		return certs.CSRPage{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	return certs.CSRPage{
		PageMetadata: pm,
		CSRs: csrs,
	}, nil
}

func (repo CSRRepo) total(ctx context.Context, query string, params interface{}) (uint64, error) {
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
