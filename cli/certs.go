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
	ctxsdk "github.com/absmach/certs/sdk"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/spf13/cobra"
)

// Keep SDK handle in global var.
var sdk ctxsdk.SDK

func SetSDK(s ctxsdk.SDK) {
	sdk = s
}

var cmdCerts = []cobra.Command{
	{
		Use:   "get [all | <entity_id>] <domain_id> <token>",
		Short: "Get certificate",
		Long:  `Gets a certificate for a given entity ID or all certificates.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			if args[0] == "all" {
				pm := ctxsdk.PageMetadata{
					Limit:  Limit,
					Offset: Offset,
				}
				page, err := sdk.ListCerts(pm, args[1], args[2])
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
			page, err := sdk.ListCerts(pm, args[1], args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, page)
		},
	},
	{
		Use:   "revoke <serial_number> <domain_id> <token>",
		Short: "Revoke certificate",
		Long:  `Revokes a certificate for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			err := sdk.RevokeCert(args[0], args[1], args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
		},
	},
	{
		Use:   "delete <entity_id> <domain_id> <token>",
		Short: "Delete certificate",
		Long:  `Deletes certificates for a given entity id.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			err := sdk.DeleteCert(args[0], args[1], args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
		},
	},
	{
		Use:   "renew <serial_number> <domain_id> <token>",
		Short: "Renew certificate",
		Long:  `Renews a certificate for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			_, err := sdk.RenewCert(args[0], args[1], args[2])
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
		Use:   "view <serial_number> <domain_id> <token>",
		Short: "View certificate",
		Long:  `Views a certificate for a given serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.ViewCert(args[0], args[1], args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	},
	{
		Use:   "view-ca",
		Short: "View-ca certificate",
		Long:  `Views ca certificate.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 0 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			cert, err := sdk.ViewCA()
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
		},
	},
	{
		Use:   "download-ca",
		Short: "Download signing CA",
		Long:  `Download intermediate cert and ca.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 0 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			bundle, err := sdk.DownloadCA()
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logSaveCAFiles(*cmd, bundle)
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
		Use:   "issue-csr <entity_id> <ttl> <path_to_csr> <domain_id> <token>",
		Short: "Issue from CSR",
		Long:  `issues a certificate for a given csr.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 5 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			csrData, err := os.ReadFile(args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			cert, err := sdk.IssueFromCSR(args[0], args[1], string(csrData), args[3], args[4])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
			logSaveCertFiles(*cmd, cert)
		},
	},
	{
		Use:   "issue-csr-internal <entity_id> <ttl> <path_to_csr> <agent_token>",
		Short: "Issue from CSR Internal (Agent)",
		Long:  `Issues a certificate for a given CSR using agent authentication.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 4 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			csrData, err := os.ReadFile(args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			cert, err := sdk.IssueFromCSRInternal(args[0], args[1], string(csrData), args[3])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
			logSaveCertFiles(*cmd, cert)
		},
	},
	{
		Use:   "crl",
		Short: "Generate CRL",
		Long:  `Generates a Certificate Revocation List (CRL).`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 0 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			crlBytes, err := sdk.GenerateCRL()
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logSaveCRLFile(*cmd, crlBytes)
		},
	},
	{
		Use:   "entity-id <serial_number> <domain_id> <token>",
		Short: "Get entity ID by serial number",
		Long:  `Gets the entity ID for a certificate by its serial number.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			entityID, err := sdk.GetEntityID(args[0], args[1], args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, map[string]string{"entity_id": entityID})
		},
	},
}

// NewCertsCmd returns certificate command.
func NewCertsCmd() *cobra.Command {
	var ttl string
	issueCmd := cobra.Command{
		Use:   "issue <entity_id> <common_name> <ip_addrs_json> [<options_json>] <domain_id> <token> [--ttl=8760h]",
		Short: "Issue certificate",
		Long:  `Issues a certificate for a given entity ID.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 5 || len(args) > 6 {
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

			var domainID, token string
			if len(args) == 5 {
				domainID = args[3]
				token = args[4]
			} else {
				if err := json.Unmarshal([]byte(args[3]), &option); err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				domainID = args[4]
				token = args[5]
			}

			cert, err := sdk.IssueCert(args[0], ttl, ipAddrs, option, domainID, token)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logJSONCmd(*cmd, cert)
			logSaveCertFiles(*cmd, cert)
		},
	}

	issueCmd.Flags().StringVar(&ttl, "ttl", "8760h", "certificate time to live in duration")

	cmd := cobra.Command{
		Use:   "certs [issue | get | revoke | renew | ocsp | view | download-ca | view-ca | csr | issue-csr | issue-csr-internal | crl | entity-id]",
		Short: "Certificates management",
		Long:  `Certificates management: issue, get all, get by entity ID, revoke, renew, OCSP, view, CRL generation, entity ID lookup, agent CSR issuing, and CA operations.`,
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

	actualKey := privKey
	if keyBytes, ok := privKey.([]byte); ok {
		actualKey, err = extractPrivateKey(keyBytes)
		if err != nil {
			return certs.CSR{}, errors.NewSDKError(errors.Wrap(certs.ErrCreateEntity, err))
		}
	}

	switch key := actualKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		signer = key.(crypto.Signer)
	case ed25519.PrivateKey:
		signer = key
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
