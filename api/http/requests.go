// Copyright (c) Ultraviolet
package http

import (
	"github.com/absmach/certs"
	"github.com/absmach/magistrala/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

var (
	ErrMissingToken      = errors.New("missing token")
	ErrMissingEntityID   = errors.New("missing entity ID")
	ErrMissingEntityType = errors.New("missing entity type")
)

type viewReq struct {
	token string
	id    string
}

func (req viewReq) validate() error {
	if req.token == "" {
		return ErrMissingToken
	}
	return nil
}

type issueCertReq struct {
	token      string   `json:"-"`
	entityID   string   `json:"-"`
	entityType string   `json:"-"`
	IpAddrs    []string `json:"ip_addresses"`
}

func (req issueCertReq) validate() error {
	if req.token == "" {
		return errors.Wrap(errors.ErrMalformedEntity, ErrMissingToken)
	}
	if req.entityID == "" {
		return errors.Wrap(errors.ErrMalformedEntity, ErrMissingEntityID)
	}
	if req.entityType == "" {
		return errors.Wrap(errors.ErrMalformedEntity, ErrMissingEntityType)
	}
	return nil
}

type listCertsReq struct {
	token string
	pm    certs.PageMetadata
}

func (req listCertsReq) validate() error {
	if req.token == "" {
		return errors.Wrap(errors.ErrMalformedEntity, ErrMissingToken)
	}
	return nil
}

type ocspReq struct {
	req         *ocsp.Request
	statusParam string
}

func (req ocspReq) validate() error {
	if req.req == nil {
		return errors.ErrMalformedEntity
	}
	return nil
}
