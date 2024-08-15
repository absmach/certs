// Copyright (c) Ultraviolet
package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/absmach/certs"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/postgres"
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
	INSERT INTO certs (serial_number, certificate, key, entity_id, entity_type, revoked, expiry_date)
	VALUES (:serial_number, :certificate, :key, :entity_id, :entity_type, :revoked, :expiry_date)`
	_, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return postgres.HandleError(err, service.ErrCreateEntity)
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
	q := `UPDATE certs SET certificate = :certificate, key = :key, revoked = :revoked, expiry_date = :expiry_date WHERE serial_number = :serial_number`
	res, err := repo.db.NamedExecContext(ctx, q, cert)
	if err != nil {
		return postgres.HandleError(err, service.ErrUpdateEntity)
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

func (repo certsRepo) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertificatePage, error) {
	q := `SELECT serial_number, revoked, expiry_date, entity_id FROM certs %s LIMIT :limit OFFSET :offset`

	if pm.EntityID != "" {
		q = fmt.Sprintf(q, "WHERE entity_id = :entity_id")
	} else {
		q = fmt.Sprintf(q, "")
	}
	var certificates []certs.Certificate

	rows, err := repo.db.NamedQueryContext(ctx, q, pm)
	if err != nil {
		return certs.CertificatePage{}, postgres.HandleError(err, service.ErrViewEntity)
	}
	defer rows.Close()

	for rows.Next() {
		cert := &certs.Certificate{}
		if err := rows.StructScan(cert); err != nil {
			return certs.CertificatePage{}, errors.Wrap(service.ErrViewEntity, err)
		}

		certificates = append(certificates, *cert)
	}

	q = `SELECT COUNT(*) FROM certs LIMIT :limit OFFSET :offset`
	pm.Total, err = repo.total(ctx, q, pm)
	if err != nil {
		return certs.CertificatePage{}, errors.Wrap(service.ErrViewEntity, err)
	}
	return certs.CertificatePage{
		Certificates: certificates,
		PageMetadata: pm,
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
