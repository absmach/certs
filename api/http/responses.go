// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	_ Response = (*revokeCertRes)(nil)
	_ Response = (*issueCertRes)(nil)
	_ Response = (*renewCertRes)(nil)
	_ Response = (*ocspRes)(nil)
)

type pageRes struct {
	Limit  uint64 `json:"limit"`
	Offset uint64 `json:"offset"`
	Total  uint64 `json:"total"`
}

type cert struct {
	SerialNumber string    `json:"serial_number"`
	Revoked      bool      `json:"revoked"`
	ExpiryTime   time.Time `json:"expiry_time"`
	EntityID     string    `json:"entity_id"`
	DownloadUrl  string    `json:"-"`
}

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
		return http.StatusOK
	}

	return http.StatusBadRequest
}

func (res revokeCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res revokeCertRes) Empty() bool {
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

type downloadCertRes struct {
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
	CA          []byte `json:"ca"`
}

func (res downloadCertRes) Code() int {
	return http.StatusOK
}

func (res downloadCertRes) Headers() map[string]string {
	return map[string]string{}
}

func (res downloadCertRes) Empty() bool {
	return false
}

type issueCertRes struct {
	SerialNumber string `json:"serial_number"`
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
	Total        uint64 `json:"total"`
	Offset       uint64 `json:"offset"`
	Limit        uint64 `json:"limit"`
	Certificates []cert `json:"certificates"`
}

func (res listCertsRes) Code() int {
	return http.StatusOK
}

func (res listCertsRes) Headers() map[string]string {
	return map[string]string{}
}

type viewCertRes struct {
	SerialNumber string    `json:"serial_number"`
	Certificate  *string   `json:"certificate"`
	Key          *string   `json:"key"`
	Revoked      bool      `json:"revoked"`
	ExpiryTime   time.Time `json:"expiry_time"`
	EntityID     string    `json:"entity_id"`
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

func (res listCertsRes) Empty() bool {
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
