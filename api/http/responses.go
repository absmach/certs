// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto"
	"crypto/x509"
	"net/http"

	"github.com/absmach/certs"
	"github.com/absmach/certs/internal/api"
	"golang.org/x/crypto/ocsp"
)

var (
	_ api.Response = (*revokeCertRes)(nil)
	_ api.Response = (*issueCertRes)(nil)
	_ api.Response = (*renewCertRes)(nil)
	_ api.Response = (*ocspRes)(nil)
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
	certs.CertificatePage
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
