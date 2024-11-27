// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/rsa"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
	"golang.org/x/crypto/ocsp"
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

type ocspReq struct {
	req         *ocsp.Request
	statusParam string
}

func (req ocspReq) validate() error {
	if req.req == nil {
		return certs.ErrMalformedEntity
	}
	return nil
}

type createCSRReq struct {
	Metadata   certs.CSRMetadata `json:"metadata"`
	PrivateKey []byte            `json:"private_Key"`
	privKey    *rsa.PrivateKey
}

func (req createCSRReq) validate() error {
	if req.Metadata.EntityID == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingEntityID)
	}
	return nil
}

type SignCSRReq struct {
	csrID   string
	approve bool
}

func (req SignCSRReq) validate() error {
	if req.csrID == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingEntityID)
	}

	return nil
}

type listCSRsReq struct {
	pm certs.PageMetadata
}

func (req listCSRsReq) validate() error {
	if req.pm.Status.String() == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingStatus)
	}
	return nil
}

type retrieveCSRReq struct {
	csrID string
}

func (req retrieveCSRReq) validate() error {
	if req.csrID == "" {
		return errors.Wrap(certs.ErrMalformedEntity, ErrMissingEntityID)
	}
	return nil
}
