// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

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

func (repo CSRRepo) CreateCSR(ctx context.Context, csr certs.CSR) error {
	q := `
	INSERT INTO csr (id, serial_number, csr, private_key, entity_id, status, submitted_at, processed_at)
	VALUES (:id, :serial_number, :csr, :private_key, :entity_id, :status, :submitted_at, :processed_at)`
	_, err := repo.db.NamedExecContext(ctx, q, csr)
	if err != nil {
		return handleError(certs.ErrCreateEntity, err)
	}
	return nil
}

func (repo CSRRepo) UpdateCSR(ctx context.Context, csr certs.CSR) error {
	q := `UPDATE csr SET serial_number = :serial_number, status = :status, private_key = :private_key, submitted_at = :submitted_at, processed_at = :processed_at WHERE id = :id`
	res, err := repo.db.NamedExecContext(ctx, q, csr)
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

func (repo CSRRepo) RetrieveCSR(ctx context.Context, id string) (certs.CSR, error) {
	q := `SELECT id, serial_number, csr, private_key, entity_id, status, submitted_at, processed_at FROM csr WHERE id = $1`
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
	var query []string
	params := map[string]interface{}{
        "limit":  pm.Limit,
        "offset": pm.Offset,
    }
	if pm.EntityID != "" {
		query = append(query, `c.entity_id = :entity_id`)
		params["entity_id"] = pm.EntityID
	}
	if pm.Status != certs.All {
		query = append(query, `c.status = :status`)
		params["status"] = pm.Status
	}

	var str string
	if len(query) > 0 {
		str = fmt.Sprintf(`WHERE %s`, strings.Join(query, ` AND `))
	}

	q := fmt.Sprintf(`
	SELECT 
		c.id,
		c.serial_number,
		c.submitted_at,
		c.processed_at, 
		c.entity_id
	FROM csr c %s LIMIT :limit OFFSET :offset;`, str)

	log.Printf("Query: %s", q)
	log.Printf("Parameters: %+v", pm)
	rows, err := repo.db.NamedQueryContext(ctx, q, pm)
	if err != nil {
		return certs.CSRPage{}, handleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()
	log.Printf("row : %+v", rows)
	var csrs []certs.CSR
	for rows.Next() {
		csr := certs.CSR{}
		if err := rows.StructScan(&csr); err != nil {
			log.Printf("StructScan error: %v", err)
			return certs.CSRPage{}, errors.Wrap(certs.ErrViewEntity, err)
		}
		log.Printf("Scanned CSR: %+v", csr)
		csrs = append(csrs, csr)
	}

	if len(csrs) == 0 {
        log.Println("No CSRs found matching the query")
    }

	cq := fmt.Sprintf(`SELECT COUNT(*) FROM csr c %s;`, str)
	pm.Total, err = repo.total(ctx, cq, pm)
	if err != nil {
		return certs.CSRPage{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	return certs.CSRPage{
		PageMetadata: pm,
		CSRs:         csrs,
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
