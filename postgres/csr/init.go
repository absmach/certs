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
				Id: "csr_1",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS csr (
						serial_number VARCHAR(40),
						csr 		  TEXT,
                        private_key   TEXT,
						entity_id     VARCHAR(36),
                    	status        BOOLEAN,
                        submitted_at  TIMESTAMP,
						processed_at  TIMESTAMP,
                        PRIMARY KEY (entity_id)
                    )`,
				},
				Down: []string{
					"DROP TABLE csr",
				},
			},
		},
	}
}
