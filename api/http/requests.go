// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
)

type downloadReq struct {
	id    string
	token string
}

func (req downloadReq) validate() error {
	if req.token == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrEmptyToken)
	}
	return nil
}

type viewReq struct {
	id string
}

func (req viewReq) validate() error {
	if req.id == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrEmptySerialNo)
	}
	return nil
}

type deleteReq struct {
	entityID string
}

func (req deleteReq) validate() error {
	if req.entityID == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingEntityID)
	}
	return nil
}

type crlReq struct {
	certtype certs.CertType
}

func (req crlReq) validate() error {
	if req.certtype != certs.IntermediateCA {
		return errors.Wrap(certs.ErrMalformedEntity, errors.New("invalid CA type"))
	}
	return nil
}

type issueCertReq struct {
	entityID string               `json:"-"`
	TTL      string               `json:"ttl"`
	IpAddrs  []string             `json:"ip_addresses"`
	Options  certs.SubjectOptions `json:"options"`
}

func (req issueCertReq) validate() error {
	if req.entityID == `""` {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingEntityID)
	}
	return nil
}

type listCertsReq struct {
	pm certs.PageMetadata
}

func (req listCertsReq) validate() error {
	return nil
}

type ocspCheckReq struct {
	SerialNumber string `json:"serial_number"`
	CertContent  string `json:"cert_content"`
	StatusParam  string `json:"status_param"`
}

func (req *ocspCheckReq) validate() error {
	if req.CertContent != "" {
		serialNumber, err := extractSerialFromCertContent(req.CertContent)
		if err != nil {
			return errors.Wrap(certs.ErrMalformedEntity, fmt.Errorf("failed to extract serial from certificate: %w", err))
		}
		req.SerialNumber = serialNumber
	}

	if req.SerialNumber == "" {
		return errors.Wrap(certs.ErrMalformedEntity, errors.New("either serial number or certificate path must be provided"))
	}

	req.SerialNumber = normalizeSerialNumber(req.SerialNumber)

	return nil
}

func normalizeSerialNumber(serial string) string {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(serial, ":", ""), " ", "")

	cleaned = strings.ToLower(cleaned)

	if len(cleaned)%2 != 0 {
		cleaned = "0" + cleaned
	}

	var result strings.Builder
	for i := 0; i < len(cleaned); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(cleaned[i : i+2])
	}

	return result.String()
}

func extractSerialFromCertContent(certContent string) (string, error) {
	certData := []byte(certContent)

	block, _ := pem.Decode(certData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	serialHex := cert.SerialNumber.Text(16)
	return normalizeSerialNumber(serialHex), nil
}

type IssueFromCSRReq struct {
	entityID string
	ttl      string
	CSR      string `json:"csr"`
}

func (req IssueFromCSRReq) validate() error {
	if req.entityID == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingEntityID)
	}
	if len(req.CSR) == 0 {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingCSR)
	}

	return nil
}
