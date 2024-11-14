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
	INSERT INTO certs (serial_number, certificate, key, entity_id, revoked, expiry_time, type)
	VALUES (:serial_number, :certificate, :key, :entity_id, :revoked, :expiry_time, :type)`
	_, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return handleError(certs.ErrCreateEntity, err)
	}
	return nil
}

// RetrieveLog retrieves computation log from the database.
func (repo certsRepo) RetrieveCert(ctx context.Context, serialNumber string) (certs.Certificate, error) {
	q := `SELECT serial_number, certificate, key, entity_id, revoked, expiry_time FROM certs WHERE serial_number = $1`
	var cert certs.Certificate
	if err := repo.db.QueryRowxContext(ctx, q, serialNumber).StructScan(&cert); err != nil {
		if err == sql.ErrNoRows {
			return certs.Certificate{}, errors.Wrap(certs.ErrNotFound, err)
		}
		return certs.Certificate{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	return cert, nil
}

// GetCAs reterives rootCA and intermediateCA from database.
func (repo certsRepo) GetCAs(ctx context.Context, caType ...certs.CertType) ([]certs.Certificate, error) {
	q := `SELECT serial_number, key, certificate, expiry_time, revoked, type FROM certs WHERE type = ANY($1)`
	var certificates []certs.Certificate

	types := make([]string, 0, len(caType))
	for i, t := range caType {
		types[i] = t.String()
	}

	if len(types) == 0 {
		types = []string{certs.RootCA.String(), certs.IntermediateCA.String()}
	}

	rows, err := repo.db.QueryContext(ctx, q, types)
	if err != nil {
		return []certs.Certificate{}, handleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	var certType string
	for rows.Next() {
		cert := &certs.Certificate{}
		if err := rows.Scan(
			&cert.SerialNumber,
			&cert.Key,
			&cert.Certificate,
			&cert.ExpiryTime,
			&cert.Revoked,
			&certType,
		); err != nil {
			return []certs.Certificate{}, errors.Wrap(certs.ErrViewEntity, err)
		}

		crtType, err := certs.CertTypeFromString(certType)
		if err != nil {
			return []certs.Certificate{}, errors.Wrap(certs.ErrViewEntity, err)
		}
		cert.Type = crtType

		certificates = append(certificates, *cert)
	}

	if err = rows.Err(); err != nil {
		return []certs.Certificate{}, errors.Wrap(certs.ErrViewEntity, err)
	}

	return certificates, nil
}

// UpdateLog updates computation log in the database.
func (repo certsRepo) UpdateCert(ctx context.Context, cert certs.Certificate) error {
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

func (repo certsRepo) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
	q := `SELECT serial_number, revoked, expiry_time, entity_id FROM certs %s LIMIT :limit OFFSET :offset`
	var condition string
	if pm.EntityID != "" {
		condition = fmt.Sprintf(`WHERE entity_id = :entity_id AND type = '%s'`, certs.ClientCert.String())
	} else {
		condition = fmt.Sprintf(`WHERE type = '%s'`, certs.ClientCert.String())
	}
	q = fmt.Sprintf(q, condition)
	var certificates []certs.Certificate

	params := map[string]interface{}{
		"limit":     pm.Limit,
		"offset":    pm.Offset,
		"entity_id": pm.EntityID,
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return certs.CertificatePage{}, handleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	for rows.Next() {
		cert := &certs.Certificate{}
		if err := rows.StructScan(cert); err != nil {
			return certs.CertificatePage{}, errors.Wrap(certs.ErrViewEntity, err)
		}

		certificates = append(certificates, *cert)
	}

	q = fmt.Sprintf(`SELECT COUNT(*) FROM certs %s LIMIT :limit OFFSET :offset`, condition)
	pm.Total, err = repo.total(ctx, q, params)
	if err != nil {
		return certs.CertificatePage{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	return certs.CertificatePage{
		PageMetadata: pm,
		Certificates: certificates,
	}, nil
}

func (repo certsRepo) ListRevokedCerts(ctx context.Context) ([]certs.Certificate, error) {
	query := `
        SELECT serial_number, entity_id, expiry_time
        FROM certs
        WHERE revoked = true
    `
	rows, err := repo.db.QueryContext(ctx, query)
	if err != nil {
		return nil, handleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	var revokedCerts []certs.Certificate
	for rows.Next() {
		var cert certs.Certificate
		if err := rows.Scan(&cert.SerialNumber, &cert.EntityID, &cert.ExpiryTime); err != nil {
			return nil, handleError(certs.ErrViewEntity, err)
		}
		revokedCerts = append(revokedCerts, cert)
	}

	return revokedCerts, nil
}

func (repo certsRepo) RemoveCerts(ctx context.Context, backendId string) error {
	q := `DELETE FROM certs WHERE entity_id = $1`

	result, err := repo.db.ExecContext(ctx, q, backendId)
	if err != nil {
		return errors.Wrap(certs.ErrViewEntity, err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return certs.ErrNotFound
	}

	return nil
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
