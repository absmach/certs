// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"

	ctxsdk "github.com/absmach/certs/sdk"
	"github.com/spf13/cobra"
)

// Keep SDK handle in global var.
var sdk ctxsdk.SDK

func SetSDK(s ctxsdk.SDK) {
	sdk = s
}

var cmdCerts = []cobra.Command{
	{
		Use:   "get [all | <entity_id> ]",
		Short: "Get certificate",
		Long:  `Gets a certificate for a given entity ID or all certificates.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			if args[0] == "all" {
				pm := ctxsdk.PageMetadata{
					Limit:  Limit,
					Offset: Offset,
				}
				page, err := sdk.ListCerts(pm)
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				logJSONCmd(*cmd, page)
				return
			}
			pm := ctxsdk.PageMetadata{
				EntityID: args[0],
				Limit:    Limit,
				Offset:   Offset,
			}
			page, err := sdk.ListCerts(pm)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, page)
		},
	},
	{
		Use:   "revoke <serial_number> ",
		Short: "Revoke certificate",
		Long:  `Revokes a certificate for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			err := sdk.RevokeCert(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
		},
	},
	{
		Use:   "issue <entity_id> '[\"<ip_addr_1>\", \"<ip_addr_2>\"]'",
		Short: "Issue certificate",
		Long:  `Issues a certificate for a given entity ID.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			var ipAddrs []string
			if err := json.Unmarshal([]byte(args[1]), &ipAddrs); err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			serial, err := sdk.IssueCert(args[0], ipAddrs)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, serial)
		},
	},
	{
		Use:   "renew <serial_number> ",
		Short: "Renew certificate",
		Long:  `Renews a certificate for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			err := sdk.RenewCert(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
		},
	},
	{
		Use:   "ocsp <serial_number> ",
		Short: "OCSP",
		Long:  `OCSP for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, status, err := sdk.OCSP(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert, status)
		},
	},
	{
		Use:   "token <serial_number> ",
		Short: "Get download token",
		Long:  `Gets a download token for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			token, err := sdk.RetrieveCertDownloadToken(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, token)
		},
	},
	{
		Use:   "download <serial_number> <token>",
		Short: "Download certificate",
		Long:  `Downloads a certificate for a given serial number and token.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.RetrieveCert(args[1], args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	},
}

// NewCertsCmd returns certificate command.
func NewCertsCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "certs [issue | get | revoke | renew | ocsp | token | download]",
		Short: "Certificates management",
		Long:  `Certificates management: issue, get all, get by entity ID, revoke, renew, OCSP, token, download.`,
	}

	for i := range cmdCerts {
		cmd.AddCommand(&cmdCerts[i])
	}

	return &cmd
}
