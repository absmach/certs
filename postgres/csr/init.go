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
				Id: "csrs_1",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS csrs (
						id            VARCHAR(36) PRIMARY KEY,
						serial_number VARCHAR(40),
						csr 		  TEXT,
                        private_key   TEXT,
						entity_id     VARCHAR(36),
                    	status        TEXT CHECK (status IN ('pending', 'signed', 'rejected')),
                        submitted_at  TIMESTAMP,
						signed_at     TIMESTAMP
                    )`,
				},
				Down: []string{
					"DROP TABLE csr",
				},
			},
		},
	}
}
