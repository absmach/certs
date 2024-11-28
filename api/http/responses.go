// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/absmach/certs"
	"golang.org/x/crypto/ocsp"
)

var (
	_ Response = (*revokeCertRes)(nil)
	_ Response = (*issueCertRes)(nil)
	_ Response = (*renewCertRes)(nil)
	_ Response = (*ocspRes)(nil)
)

type renewCertRes struct {
	renewed bool
}

func (res renewCertRes) Code() int {
	if res.renewed {
		return http.StatusOK
	}

	return http.StatusBadRequest
}

func (res renewCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res renewCertRes) Empty() bool {
	return true
}

type revokeCertRes struct {
	revoked bool
}

func (res revokeCertRes) Code() int {
	if res.revoked {
		return http.StatusNoContent
	}

	return http.StatusUnprocessableEntity
}

func (res revokeCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res revokeCertRes) Empty() bool {
	return true
}

type deleteCertRes struct {
	deleted bool
}

func (res deleteCertRes) Code() int {
	if res.deleted {
		return http.StatusNoContent
	}

	return http.StatusUnprocessableEntity
}

func (res deleteCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res deleteCertRes) Empty() bool {
	return true
}

type requestCertDownloadTokenRes struct {
	Token string `json:"token"`
}

func (res requestCertDownloadTokenRes) Code() int {
	return http.StatusOK
}

func (res requestCertDownloadTokenRes) Headers() map[string]string {
	return map[string]string{}
}

func (res requestCertDownloadTokenRes) Empty() bool {
	return false
}

type issueCertRes struct {
	SerialNumber string    `json:"serial_number"`
	Certificate  string    `json:"certificate,omitempty"`
	Revoked      bool      `json:"revoked"`
	ExpiryTime   time.Time `json:"expiry_time"`
	EntityID     string    `json:"entity_id"`
	issued       bool
}

func (res issueCertRes) Code() int {
	if res.issued {
		return http.StatusCreated
	}

	return http.StatusBadRequest
}

func (res issueCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res issueCertRes) Empty() bool {
	return false
}

type listCertsRes struct {
	Total        uint64        `json:"total"`
	Offset       uint64        `json:"offset"`
	Limit        uint64        `json:"limit"`
	Certificates []viewCertRes `json:"certificates"`
}

func (res listCertsRes) Code() int {
	return http.StatusOK
}

func (res listCertsRes) Headers() map[string]string {
	return map[string]string{}
}

func (res listCertsRes) Empty() bool {
	return false
}

type viewCertRes struct {
	SerialNumber string    `json:"serial_number,omitempty"`
	Certificate  string    `json:"certificate,omitempty"`
	Key          string    `json:"key,omitempty"`
	Revoked      bool      `json:"revoked,omitempty"`
	ExpiryTime   time.Time `json:"expiry_time,omitempty"`
	EntityID     string    `json:"entity_id,omitempty"`
}

func (res viewCertRes) Code() int {
	return http.StatusOK
}

func (res viewCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res viewCertRes) Empty() bool {
	return false
}

type crlRes struct {
	CrlBytes []byte `json:"crl"`
}

func (res crlRes) Code() int {
	return http.StatusOK
}

func (res crlRes) Headers() map[string]string {
	return map[string]string{}
}

func (res crlRes) Empty() bool {
	return false
}

type ocspRes struct {
	template   ocsp.Response
	signer     crypto.Signer
	issuerCert *x509.Certificate
}

func (res ocspRes) Code() int {
	return http.StatusOK
}

func (res ocspRes) Headers() map[string]string {
	return map[string]string{}
}

func (res ocspRes) Empty() bool {
	return false
}

type fileDownloadRes struct {
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
	CA          []byte `json:"ca"`
	Filename    string
	ContentType string
}

type createCSRRes struct {
	certs.CSR
	created bool
}

func (res createCSRRes) Code() int {
	if res.created {
		return http.StatusCreated
	}

	return http.StatusNoContent
}

func (res createCSRRes) Headers() map[string]string {
	return map[string]string{}
}

func (res createCSRRes) Empty() bool {
	return false
}

type signCSRRes struct {
	crt    certs.Certificate
	signed bool
}

func (res signCSRRes) Code() int {
	return http.StatusOK
}

func (res signCSRRes) Headers() map[string]string {
	return map[string]string{}
}

func (res signCSRRes) Empty() bool {
	return false
}
