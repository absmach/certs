// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"github.com/absmach/certs"
	"github.com/absmach/certs/pkg/errors"
	"github.com/absmach/certs/pkg/errors/service"
	"golang.org/x/crypto/ocsp"
)

var (
	ErrMissingEntityID   = errors.New("missing entity ID")
	ErrMissingEntityType = errors.New("missing entity type")
	ErrMissingID		 = errors.New("missing ID")
)

type downloadReq struct {
	id    string
	token string
}

func (req downloadReq) validate() error {
	if req.id == "" {
		return ErrMissingEntityID
	}
	return nil
}

type viewReq struct {
	id     string
}

func (req viewReq) validate() error {
	if req.id == "" {
		return ErrMissingID
	}
	return nil
}

type issueCertReq struct {
	entityID   string   `json:"-"`
	entityType string   `json:"-"`
	IpAddrs    []string `json:"ip_addresses"`
}

func (req issueCertReq) validate() error {
	if req.entityID == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingEntityID)
	}
	if req.entityType == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingEntityType)
	}
	return nil
}

type listCertsReq struct {
	pm     certs.PageMetadata
}

func (req listCertsReq) validate() error {
	if req.pm.EntityID == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingEntityID)
	}
	return nil
}

type ocspReq struct {
	req         *ocsp.Request
	statusParam string
}

func (req ocspReq) validate() error {
	if req.req == nil {
		return service.ErrMalformedEntity
	}
	return nil
}
