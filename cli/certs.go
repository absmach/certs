// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/absmach/certs/errors"
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
		Use:   "get [all | <entity_id>]",
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
		Use:   "delete <entity_id> ",
		Short: "Delete certificate",
		Long:  `Deletes certificates for a given entity id.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			err := sdk.DeleteCert(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
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
		Use:   "ocsp <serial_number_or_certificate_path>",
		Short: "OCSP",
		Long:  `OCSP for a given serial number or certificate.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			var serialNumber, certContent string

			if _, statErr := os.Stat(args[0]); statErr == nil {
				certBytes, err := os.ReadFile(args[0])
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				certContent = string(certBytes)
			} else {
				serialNumber = args[0]
			}

			response, err := sdk.OCSP(serialNumber, certContent)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, response)
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
			certBundle, err := sdk.DownloadCert(args[1], args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logSaveCertFiles(*cmd, certBundle)
		},
	},
	{
		Use:   "view <serial_number>",
		Short: "View certificate",
		Long:  `Views a certificate for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.ViewCert(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	},
	{
		Use:   "view-ca <token>",
		Short: "View-ca certificate",
		Long:  `Views ca certificate key with a given token.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.ViewCA(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	},
	{
		Use:   "download-ca <token>",
		Short: "Download signing CA",
		Long:  `Download intermediate cert and ca with a given token.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			bundle, err := sdk.DownloadCA(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logSaveCAFiles(*cmd, bundle)
		},
	},
	{
		Use:   "token-ca",
		Short: "Get CA token",
		Long:  `Gets a download token for CA.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 0 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			token, err := sdk.GetCAToken()
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, token)
		},
	},
	{
		Use:   "csr <metadata> <private_key_path>",
		Short: "Create CSR",
		Long:  `Creates a CSR.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 3 || len(args) == 0 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			var pm ctxsdk.PageMetadata
			if err := json.Unmarshal([]byte(args[0]), &pm); err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			var csr ctxsdk.CSR
			var err error
			if len(args) == 1 {
				csr, err = sdk.CreateCSR(pm, []byte{})
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				logJSONCmd(*cmd, csr)
				return
			}

			data, err := os.ReadFile(args[1])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			csr, err = sdk.CreateCSR(pm, data)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, csr)
		},
	},
	{
		Use:   "sign <csr_id> <sign>",
		Short: "Sign CSR",
		Long:  `Signs a CSR for a given csr id.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			var sign bool
			switch args[1] {
			case "true":
				sign = true
			case "false":
				sign = false
			default:
				logErrorCmd(*cmd, errors.NewSDKError(fmt.Errorf("unknown type")))
				return
			}

			err := sdk.SignCSR(args[0], sign)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
		},
	},
	{
		Use:   "get-csr [all | <entity_id>] <status>",
		Short: "Get csr",
		Long:  `Gets CSRs for a given entity ID or all CSR.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			if args[0] == "all" {
				pm := ctxsdk.PageMetadata{
					Limit:  Limit,
					Offset: Offset,
					Status: args[1],
				}
				page, err := sdk.ListCSRs(pm)
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
				Status:   args[1],
			}
			page, err := sdk.ListCSRs(pm)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, page)
		},
	},
	{
		Use:   "view-csr <csr_id>",
		Short: "View CSR",
		Long:  `Views a CSR for a given csr id.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.RetrieveCSR(args[0])
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
	var ttl string
	issueCmd := cobra.Command{
		Use:   "issue <entity_id> <common_name> '[\"<ip_addr_1>\", \"<ip_addr_2>\"] '{\"organization\":[\"organization_name\"]}' [--ttl=8760h]",
		Short: "Issue certificate",
		Long:  `Issues a certificate for a given entity ID.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 3 || len(args) > 4 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			var ipAddrs []string
			if err := json.Unmarshal([]byte(args[2]), &ipAddrs); err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			var option ctxsdk.Options
			option.CommonName = args[1]

			if len(args) == 4 {
				if err := json.Unmarshal([]byte(args[3]), &option); err != nil {
					logErrorCmd(*cmd, err)
					return
				}
			}

			cert, err := sdk.IssueCert(args[0], ttl, ipAddrs, option)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	}

	issueCmd.Flags().StringVar(&ttl, "ttl", "8760h", "certificate time to live in duration")

	cmd := cobra.Command{
		Use:   "certs [issue | get | revoke | renew | ocsp | token | download]",
		Short: "Certificates management",
		Long:  `Certificates management: issue, get all, get by entity ID, revoke, renew, OCSP, token, download.`,
	}

	cmd.AddCommand(&issueCmd)

	for i := range cmdCerts {
		cmd.AddCommand(&cmdCerts[i])
	}

	return &cmd
}
