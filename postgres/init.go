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
                        expiry_time    TIMESTAMP,
						entity_id      VARCHAR(36),
						type 		   TEXT CHECK (type IN ('RootCA', 'IntermediateCA', 'ClientCert')),
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
