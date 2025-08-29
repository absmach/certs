// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"

	"github.com/absmach/certs"
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
			_, err := sdk.RenewCert(args[0])
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
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			var pm certs.CSRMetadata
			if err := json.Unmarshal([]byte(args[0]), &pm); err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			data, err := os.ReadFile(args[1])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			csr, err := CreateCSR(pm, data)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logSaveCSRFiles(*cmd, csr)
		},
	},
	{
		Use:   "issue-csr <entity_id> <ttl> <path_to_csr>",
		Short: "Issue from CSR",
		Long:  `issues a certificate for a given csr.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			csrData, err := os.ReadFile(args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			cert, err := sdk.IssueFromCSR(args[0], args[1], string(csrData))
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	},
	{
		Use:   "crl [root | intermediate]",
		Short: "Generate Certificate Revocation List",
		Long:  `Generates a Certificate Revocation List (CRL) for the specified CA type.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			
			var certType ctxsdk.CertType
			switch args[0] {
			case "root":
				certType = ctxsdk.RootCA
			case "intermediate":
				certType = ctxsdk.IntermediateCA
			default:
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			
			crlBytes, err := sdk.GenerateCRL(certType)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logSaveCRLFile(*cmd, crlBytes, args[0])
		},
	},
	{
		Use:   "entity-id <serial_number>",
		Short: "Get entity ID by serial number",
		Long:  `Gets the entity ID for a certificate by its serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			entityID, err := sdk.GetEntityID(args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, map[string]string{"entity_id": entityID})
		},
	},
	{
		Use:   "ca",
		Short: "Get CA certificate",
		Long:  `Gets the CA certificate without requiring a token.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 0 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.GetCA()
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
		Use:   "certs [issue | get | revoke | renew | ocsp | token | download | download-ca | view-ca | token-ca | csr | issue-csr | crl | entity-id | ca]",
		Short: "Certificates management",
		Long:  `Certificates management: issue, get all, get by entity ID, revoke, renew, OCSP, token, download, CRL generation, entity ID lookup, and CA operations.`,
	}

	cmd.AddCommand(&issueCmd)

	for i := range cmdCerts {
		cmd.AddCommand(&cmdCerts[i])
	}

	return &cmd
}

func CreateCSR(metadata certs.CSRMetadata, privKey any) (certs.CSR, errors.SDKError) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         metadata.CommonName,
			Organization:       metadata.Organization,
			OrganizationalUnit: metadata.OrganizationalUnit,
			Country:            metadata.Country,
			Province:           metadata.Province,
			Locality:           metadata.Locality,
			StreetAddress:      metadata.StreetAddress,
			PostalCode:         metadata.PostalCode,
		},
		EmailAddresses:  metadata.EmailAddresses,
		DNSNames:        metadata.DNSNames,
		ExtraExtensions: metadata.ExtraExtensions,
	}

	for _, ip := range metadata.IPAddresses {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			template.IPAddresses = append(template.IPAddresses, parsedIP)
		}
	}

	var signer crypto.Signer
	var err error

	switch key := privKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		signer = key.(crypto.Signer)
	case ed25519.PrivateKey:
		signer = key
	case []byte:
		parsedKey, err := extractPrivateKey(key)
		if err != nil {
			return certs.CSR{}, errors.NewSDKError(errors.Wrap(certs.ErrCreateEntity, err))
		}
		return CreateCSR(metadata, parsedKey)
	default:
		return certs.CSR{}, errors.NewSDKError(errors.Wrap(certs.ErrCreateEntity, certs.ErrPrivKeyType))
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return certs.CSR{}, errors.NewSDKError(errors.Wrap(certs.ErrCreateEntity, err))
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	csr := certs.CSR{
		CSR: csrPEM,
	}

	return csr, nil
}

func extractPrivateKey(pemKey []byte) (any, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("failed to parse private key PEM")
	}

	var (
		privateKey any
		err        error
	)

	switch block.Type {
	case certs.RSAPrivateKey:
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case certs.ECPrivateKey:
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case certs.PrivateKey, certs.PKCS8PrivateKey, certs.EDPrivateKey:
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		err = certs.ErrPrivKeyType
	}
	if err != nil {
		return nil, certs.ErrFailedParse
	}

	return privateKey, nil
}
