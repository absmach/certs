// Copyright (c) Ultraviolet
package http

import (
	"github.com/absmach/certs"
	"github.com/absmach/certs/pkg/errors"
	"github.com/absmach/certs/pkg/errors/service"
	"golang.org/x/crypto/ocsp"
)

var (
	ErrMissingUserId      = errors.New("missing user ID")
	ErrMissingEntityID   = errors.New("missing entity ID")
	ErrMissingEntityType = errors.New("missing entity type")
)

type viewReq struct {
	userId string
	id    string
}

func (req viewReq) validate() error {
	if req.userId == "" {
		return ErrMissingUserId
	}
	return nil
}

type issueCertReq struct {
	userId      string   `json:"-"`
	entityID   string   `json:"-"`
	entityType string   `json:"-"`
	IpAddrs    []string `json:"ip_addresses"`
}

func (req issueCertReq) validate() error {
	if req.userId == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingUserId)
	}
	if req.entityID == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingEntityID)
	}
	if req.entityType == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingEntityType)
	}
	return nil
}

type listCertsReq struct {
	userId string
	pm    certs.PageMetadata
}

func (req listCertsReq) validate() error {
	if req.userId == "" {
		return errors.Wrap(service.ErrMalformedEntity, ErrMissingUserId)
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
