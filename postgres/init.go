// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	_ "github.com/jackc/pgx/v5/stdlib"
	migrate "github.com/rubenv/sql-migrate"
)

func Migration() *migrate.MemoryMigrationSource {
	return &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "certs_1",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS certs (
						serial_number VARCHAR(40) UNIQUE NOT NULL,
                        certificate    TEXT,
                    	key            TEXT,
                    	revoked        BOOLEAN,
                        expiry_date    TIMESTAMP,
						entity_type    VARCHAR(20),
						entity_id      VARCHAR(36),
						created_by     VARCHAR(36),
						created_at     TIMESTAMP,
						updated_by     VARCHAR(36),
						updated_at     TIMESTAMP,
                        PRIMARY KEY (serial_number)
                    )`,
				},
				Down: []string{
					"DROP TABLE certs",
				},
			},
		},
	}
}
