// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"log/slog"

	"github.com/absmach/certs"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/domains/events/consumer"
	"github.com/absmach/supermq/pkg/events"
	"github.com/mitchellh/mapstructure"
)

const (
	domainPrefix  = "domain."
	domainCreate  = domainPrefix + "create"
	domainDisable = domainPrefix + "disable"
)

type eventMessage struct {
	Operation string
}

type createDomainEvent struct {
	domainID  string
	createdBy string
}

func decodeCreateDomain(event map[string]any) createDomainEvent {
	d, err := consumer.ToDomains(event)
	if err != nil {
		return createDomainEvent{}
	}

	cde := createDomainEvent{
		domainID:  d.ID,
		createdBy: d.CreatedBy,
	}

	return cde
}

func read(event map[string]any, key, def string) string {
	val := event[key]
	valStr, ok := val.(string)
	if !ok {
		return def
	}

	if valStr == "" {
		return def
	}

	return valStr
}

// EventHandler handles domain events and creates CAs for new domains.
type EventHandler struct {
	svc              certs.Service
	logger           *slog.Logger
	defaultCAOptions certs.CAOptions
}

// NewEventHandler creates a new event handler for domain events.
func NewEventHandler(svc certs.Service, logger *slog.Logger, defaultCAOptions certs.CAOptions) *EventHandler {
	return &EventHandler{
		svc:              svc,
		logger:           logger,
		defaultCAOptions: defaultCAOptions,
	}
}

// Handle processes domain events and creates CA infrastructure for new domains.
func (h *EventHandler) Handle(ctx context.Context, event events.Event) error {
	msg, err := event.Encode()
	if err != nil {
		return err
	}

	var ev eventMessage
	if err := mapstructure.Decode(msg, &ev); err != nil {
		return err
	}

	switch ev.Operation {
	case domainCreate:
		return h.handleDomainCreate(ctx, msg)
	case domainDisable:
		return h.handleDomainDisable(ctx, msg)
	default:
		return nil
	}
}

func (h *EventHandler) handleDomainCreate(ctx context.Context, event map[string]any) error {
	domainEvent := decodeCreateDomain(event)
	if domainEvent.domainID == "" {
		h.logger.Warn("domain create event missing domain ID")
		return nil
	}

	h.logger.Info("Creating CA for new domain", "domain_id", domainEvent.domainID, "created_by", domainEvent.createdBy)

	// Use default CA options but override CommonName with domain ID
	options := h.defaultCAOptions
	options.CommonName = domainEvent.domainID

	// Create domain CA infrastructure
	if err := h.svc.CreateDomainCA(ctx, domainEvent.domainID, domainEvent.createdBy, options); err != nil {
		h.logger.Error("Failed to create domain CA", "domain_id", domainEvent.domainID, "error", err)
		return err
	}

	h.logger.Info("Successfully created CA for domain", "domain_id", domainEvent.domainID)
	return nil
}

func (h *EventHandler) handleDomainDisable(ctx context.Context, event map[string]any) error {
	domainEvent := decodeCreateDomain(event)
	if domainEvent.domainID == "" {
		h.logger.Warn("domain disable event missing domain ID")
		return nil
	}

	h.logger.Info("Domain disabled, revoking all certificates", "domain_id", domainEvent.domainID)

	// Create a session for the domain to route certificate operations to the correct namespace
	session := authn.Session{
		DomainID:     domainEvent.domainID,
		UserID:       domainEvent.createdBy,
		DomainUserID: domainEvent.createdBy,
	}

	// Revoke all certificates for the domain (using domain ID as entity ID)
	if err := h.svc.RevokeAll(ctx, session, domainEvent.domainID); err != nil {
		h.logger.Error("Failed to revoke certificates for domain", "domain_id", domainEvent.domainID, "error", err)
		return err
	}

	h.logger.Info("Successfully revoked all certificates for domain", "domain_id", domainEvent.domainID)
	return nil
}
