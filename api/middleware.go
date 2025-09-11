// Copyright (c) Ultraviolet

package api

import (
	"context"
	"fmt"

	crt "github.com/absmach/certs"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/authz"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/policies"
)

var _ crt.Service = (*authorizationMiddleware)(nil)

type authorizationMiddleware struct {
	authz authz.Authorization
	svc   crt.Service
}

func AuthorizationMiddleware(authz authz.Authorization, svc crt.Service) crt.Service {
	return &authorizationMiddleware{authz, svc}
}

func (am *authorizationMiddleware) RenewCert(ctx context.Context, session authn.Session, serialNumber string) (crt.Certificate, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return crt.Certificate{}, err
	}
	return am.svc.RenewCert(ctx, session, serialNumber)
}

func (am *authorizationMiddleware) RetrieveCert(ctx context.Context, session authn.Session, token, serialNumber string) (crt.Certificate, []byte, error) {
	return am.svc.RetrieveCert(ctx, session, token, serialNumber)
}

func (am *authorizationMiddleware) RevokeBySerial(ctx context.Context, session authn.Session, serialNumber string) error {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return err
	}
	return am.svc.RevokeBySerial(ctx, session, serialNumber)
}

func (am *authorizationMiddleware) RevokeAll(ctx context.Context, session authn.Session, entityID string) error {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return err
	}
	return am.svc.RevokeAll(ctx, session, entityID)
}

func (am *authorizationMiddleware) RetrieveCertDownloadToken(ctx context.Context, session authn.Session, serialNumber string) (string, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return "", err
	}
	return am.svc.RetrieveCertDownloadToken(ctx, session, serialNumber)
}

func (am *authorizationMiddleware) IssueCert(ctx context.Context, session authn.Session, entityID, ttl string, ipAddrs []string, options crt.SubjectOptions) (crt.Certificate, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return crt.Certificate{}, err
	}
	return am.svc.IssueCert(ctx, session, entityID, ttl, ipAddrs, options)
}

func (am *authorizationMiddleware) ListCerts(ctx context.Context, session authn.Session, pm crt.PageMetadata) (crt.CertificatePage, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return crt.CertificatePage{}, err
	}
	return am.svc.ListCerts(ctx, session, pm)
}

func (am *authorizationMiddleware) ViewCert(ctx context.Context, session authn.Session, serialNumber string) (crt.Certificate, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return crt.Certificate{}, err
	}
	return am.svc.ViewCert(ctx, session, serialNumber)
}

func (am *authorizationMiddleware) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	return am.svc.GetEntityID(ctx, serialNumber)
}

func (am *authorizationMiddleware) RetrieveCAToken(ctx context.Context, session authn.Session) (string, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return "", err
	}
	return am.svc.RetrieveCAToken(ctx, session)
}

func (am *authorizationMiddleware) OCSP(ctx context.Context, session authn.Session, serialNumber string) ([]byte, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return nil, err
	}
	return am.svc.OCSP(ctx, session, serialNumber)
}

func (am *authorizationMiddleware) GenerateCRL(ctx context.Context, session authn.Session, caType crt.CertType) ([]byte, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return nil, err
	}
	return am.svc.GenerateCRL(ctx, session, caType)
}

func (am *authorizationMiddleware) GetChainCA(ctx context.Context, session authn.Session, token string) (crt.Certificate, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return crt.Certificate{}, err
	}
	return am.svc.GetChainCA(ctx, session, token)
}

func (am *authorizationMiddleware) IssueFromCSR(ctx context.Context, session authn.Session, entityID, ttl string, csr crt.CSR) (crt.Certificate, error) {
	if err := am.checkUserDomainPermission(ctx, session, policies.MembershipPermission); err != nil {
		return crt.Certificate{}, err
	}
	return am.svc.IssueFromCSR(ctx, session, entityID, ttl, csr)
}

func (am *authorizationMiddleware) checkSuperAdmin(ctx context.Context, adminID string) error {
	if err := am.authz.Authorize(ctx, authz.PolicyReq{
		SubjectType: policies.UserType,
		Subject:     adminID,
		Permission:  policies.AdminPermission,
		ObjectType:  policies.PlatformType,
		Object:      policies.SuperMQObject,
	}); err != nil {
		return err
	}
	return nil
}

func (am *authorizationMiddleware) checkUserDomainPermission(ctx context.Context, session authn.Session, permission string) error {
	if err := am.checkAdmin(ctx, session.UserID); err == nil {
		return nil
	}

	if err := am.checkDomainAdmin(ctx, session.UserID, session.DomainID); err == nil {
		return nil
	}

	req := authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		SubjectKind: policies.UsersKind,
		Subject:     session.DomainUserID,
		Permission:  permission,
		ObjectType:  policies.DomainType,
		Object:      session.DomainID,
	}
	if err := am.authz.Authorize(ctx, req); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	return nil
}

func (am *authorizationMiddleware) checkAdmin(ctx context.Context, adminID string) error {
	if err := am.checkSuperAdmin(ctx, adminID); err == nil {
		return nil
	}

	if err := am.authz.Authorize(ctx, authz.PolicyReq{
		SubjectType: policies.UserType,
		SubjectKind: policies.UsersKind,
		Subject:     adminID,
		Relation:    policies.AdministratorRelation,
		Permission:  policies.AdminPermission,
		ObjectType:  policies.PlatformType,
		Object:      policies.SuperMQObject,
	}); err != nil {
		return err
	}

	return nil
}

func (am *authorizationMiddleware) checkDomainAdmin(ctx context.Context, usrID, domainID string) error {
	if err := am.authz.Authorize(ctx, authz.PolicyReq{
		Domain:      domainID,
		SubjectType: policies.UserType,
		SubjectKind: policies.UsersKind,
		Subject:     fmt.Sprintf("%s_%s", domainID, usrID),
		Permission:  policies.AdminPermission,
		ObjectType:  policies.DomainType,
		Object:      domainID,
	}); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}

	return nil
}
