// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package pki wraps OpenBao client for PKI operations
package pki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/api/v2"
)

const (
	issue     = "issue"
	sign      = "sign"
	cert      = "cert"
	revoke    = "revoke"
	ca        = "ca"
	caChain   = "ca_chain"
	crl       = "crl"
	ocsp      = "ocsp"
	certsList = "certs"
)

var (
	errFailedToLogin = errors.New("failed to login to OpenBao")
	errNoAuthInfo    = errors.New("no auth information from OpenBao")
	errRenewWatcher  = errors.New("unable to initialize new lifetime watcher for renewing auth token")
)

// Agent represents the OpenBao PKI interface.
type Agent interface {
	Issue(entityId, ttl string, ipAddrs []string, options certs.SubjectOptions) (certs.Certificate, error)
	View(serialNumber string) (certs.Certificate, error)
	Revoke(serialNumber string) error
	ListCerts(pm certs.PageMetadata) (certs.CertificatePage, error)
	GetCA() ([]byte, error)
	GetCAChain() ([]byte, error)
	GetCRL() ([]byte, error)
	SignCSR(csr []byte, entityId, ttl string) (certs.Certificate, error)
	Renew(serialNumber string, increment string) (certs.Certificate, error)
}

type openbaoPKIAgent struct {
	appRole    string
	appSecret  string
	namespace  string
	path       string
	role       string
	host       string
	issueURL   string
	signURL    string
	readURL    string
	revokeURL  string
	caURL      string
	caChainURL string
	crlURL     string
	ocspURL    string
	certsURL   string
	client     *api.Client
	secret     *api.Secret
	logger     *slog.Logger
}

// NewAgent instantiates an OpenBao PKI client that implements certs.Agent.
func NewAgent(appRole, appSecret, host, namespace, path, role string, logger *slog.Logger) (certs.Agent, error) {
	conf := api.DefaultConfig()
	conf.Address = host

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	p := openbaoPKIAgent{
		appRole:    appRole,
		appSecret:  appSecret,
		host:       host,
		namespace:  namespace,
		role:       role,
		path:       path,
		client:     client,
		logger:     logger,
		issueURL:   "/" + path + "/" + issue + "/" + role,
		signURL:    "/" + path + "/" + sign + "/" + role,
		readURL:    "/" + path + "/" + cert + "/",
		revokeURL:  "/" + path + "/" + revoke,
		caURL:      "/" + path + "/" + ca,
		caChainURL: "/" + path + "/" + caChain,
		crlURL:     "/" + path + "/" + crl,
		ocspURL:    "/" + path + "/" + ocsp,
		certsURL:   "/" + path + "/" + certsList,
	}
	return &p, nil
}

func (va *openbaoPKIAgent) Issue(entityId, ttl string, ipAddrs []string, options certs.SubjectOptions) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	secretValues := map[string]interface{}{
		"common_name":          entityId,
		"ttl":                  ttl,
		"exclude_cn_from_sans": true,
	}

	if options.CommonName != "" {
		secretValues["common_name"] = options.CommonName
	}
	if len(options.Organization) > 0 {
		secretValues["organization"] = options.Organization
	}
	if len(options.OrganizationalUnit) > 0 {
		secretValues["ou"] = options.OrganizationalUnit
	}
	if len(options.Country) > 0 {
		secretValues["country"] = options.Country
	}
	if len(options.Province) > 0 {
		secretValues["province"] = options.Province
	}
	if len(options.Locality) > 0 {
		secretValues["locality"] = options.Locality
	}
	if len(options.StreetAddress) > 0 {
		secretValues["street_address"] = options.StreetAddress
	}
	if len(options.PostalCode) > 0 {
		secretValues["postal_code"] = options.PostalCode
	}

	allDNSNames := make([]string, 0)
	allDNSNames = append(allDNSNames, options.DnsNames...)
	if len(allDNSNames) > 0 {
		secretValues["alt_names"] = allDNSNames
	}

	allIPs := make([]string, 0)
	allIPs = append(allIPs, ipAddrs...)
	for _, ip := range options.IpAddresses {
		allIPs = append(allIPs, ip.String())
	}
	if len(allIPs) > 0 {
		secretValues["ip_sans"] = allIPs
	}

	secret, err := va.client.Logical().Write(va.issueURL, secretValues)
	if err != nil {
		return certs.Certificate{}, err
	}

	if secret == nil || secret.Data == nil {
		return certs.Certificate{}, fmt.Errorf("no certificate data returned from OpenBao")
	}

	cert := certs.Certificate{
		EntityID: entityId,
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
	}

	if keyData, ok := secret.Data["private_key"].(string); ok {
		cert.Key = []byte(keyData)
	}

	if serialNumber, ok := secret.Data["serial_number"].(string); ok {
		cert.SerialNumber = serialNumber
	}

	if expirationInterface, ok := secret.Data["expiration"]; ok {
		switch exp := expirationInterface.(type) {
		case int64:
			cert.ExpiryTime = time.Unix(exp, 0)
		case float64:
			cert.ExpiryTime = time.Unix(int64(exp), 0)
		case json.Number:
			if expInt, err := exp.Int64(); err == nil {
				cert.ExpiryTime = time.Unix(expInt, 0)
			}
		}
	}

	return cert, nil
}

func (va *openbaoPKIAgent) View(serialNumber string) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	secret, err := va.client.Logical().Read(va.readURL + serialNumber)
	if err != nil {
		return certs.Certificate{}, err
	}

	if secret == nil || secret.Data == nil {
		return certs.Certificate{}, fmt.Errorf("certificate not found")
	}

	cert := certs.Certificate{
		SerialNumber: serialNumber,
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
	}

	if len(cert.Certificate) > 0 {
		if expiry, err := va.parseCertificateExpiry(string(cert.Certificate)); err == nil {
			cert.ExpiryTime = expiry
		}

		if entityID, err := va.parseCertificateEntityID(string(cert.Certificate)); err == nil {
			cert.EntityID = entityID
		}
	}

	return cert, nil
}

func (va *openbaoPKIAgent) parseCertificateExpiry(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return cert.NotAfter, nil
}

func (va *openbaoPKIAgent) parseCertificateEntityID(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return cert.Subject.CommonName, nil
}

func (va *openbaoPKIAgent) Renew(serialNumber string, increment string) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	leasePath := va.readURL + serialNumber
	lease, err := va.client.Sys().Renew(leasePath, 0)
	if err != nil {
		return certs.Certificate{}, fmt.Errorf("failed to renew certificate lease: %w", err)
	}

	if lease == nil || lease.Data == nil {
		return certs.Certificate{}, fmt.Errorf("no renewal data returned from OpenBao")
	}

	cert := certs.Certificate{
		SerialNumber: serialNumber,
	}

	if certData, ok := lease.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
		if expiry, err := va.parseCertificateExpiry(certData); err == nil {
			cert.ExpiryTime = expiry
		}
		
		if entityID, err := va.parseCertificateEntityID(certData); err == nil {
			cert.EntityID = entityID
		}
	}

	return cert, nil
}

func (va *openbaoPKIAgent) Revoke(serialNumber string) error {
	err := va.LoginAndRenew()
	if err != nil {
		return err
	}

	secretValues := map[string]interface{}{
		"serial_number": serialNumber,
	}

	_, err = va.client.Logical().Write(va.revokeURL, secretValues)
	if err != nil {
		return err
	}
	return nil
}

func (va *openbaoPKIAgent) ListCerts(pm certs.PageMetadata) (certs.CertificatePage, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.CertificatePage{}, err
	}

	secret, err := va.client.Logical().List(va.certsURL)
	if err != nil {
		return certs.CertificatePage{}, err
	}

	certPage := certs.CertificatePage{
		Certificates: []certs.Certificate{},
		PageMetadata: pm,
	}

	if secret == nil || secret.Data == nil {
		return certPage, nil
	}

	keysInterface, ok := secret.Data["keys"]
	if !ok {
		return certPage, nil
	}

	var serialNumbers []string
	if err := mapstructure.Decode(keysInterface, &serialNumbers); err != nil {
		return certPage, fmt.Errorf("failed to decode certificate serial numbers: %w", err)
	}

	var filteredCerts []certs.Certificate
	for _, serialNumber := range serialNumbers {
		cert, err := va.View(serialNumber)
		if err != nil {
			va.logger.Warn("failed to retrieve certificate details", "serial", serialNumber, "error", err)
			continue
		}

		if pm.EntityID != "" {
			if cert.EntityID != pm.EntityID {
				continue
			}
		}

		filteredCerts = append(filteredCerts, cert)
	}

	certPage.Total = uint64(len(filteredCerts))

	start := pm.Offset
	end := pm.Offset + pm.Limit
	if pm.Limit == 0 {
		end = uint64(len(filteredCerts))
	}
	if start >= uint64(len(filteredCerts)) {
		return certPage, nil
	}
	if end > uint64(len(filteredCerts)) {
		end = uint64(len(filteredCerts))
	}

	for i := start; i < end; i++ {
		certPage.Certificates = append(certPage.Certificates, filteredCerts[i])
	}

	return certPage, nil
}

func (va *openbaoPKIAgent) LoginAndRenew() error {
	if va.secret != nil && va.secret.Auth != nil && va.secret.Auth.ClientToken != "" {
		_, err := va.client.Auth().Token().LookupSelf()
		if err == nil {
			return nil
		}
	}

	authData := map[string]interface{}{
		"role_id":   va.appRole,
		"secret_id": va.appSecret,
	}

	authResp, err := va.client.Logical().Write("auth/approle/login", authData)
	if err != nil {
		return fmt.Errorf("%s: %w", errFailedToLogin, err)
	}

	if authResp == nil || authResp.Auth == nil {
		return errNoAuthInfo
	}

	va.secret = authResp
	va.client.SetToken(authResp.Auth.ClientToken)

	if authResp.Auth.Renewable {
		watcher, err := va.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
			Secret: authResp,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", errRenewWatcher, err)
		}

		go va.renewToken(watcher)
	}

	return nil
}

func (va *openbaoPKIAgent) renewToken(watcher *api.LifetimeWatcher) {
	defer watcher.Stop()

	watcher.Start()
	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				va.logger.Error("token renewal failed", "error", err)
			}
			return
		case renewal := <-watcher.RenewCh():
			va.logger.Info("token renewed successfully", "lease_duration", renewal.Secret.LeaseDuration)
		}
	}
}

func (va *openbaoPKIAgent) GetCA() ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	secret, err := va.client.Logical().Read(va.caURL)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no CA certificate data returned from OpenBao")
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		return []byte(certData), nil
	}

	return nil, fmt.Errorf("CA certificate not found in response")
}

func (va *openbaoPKIAgent) GetCAChain() ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	secret, err := va.client.Logical().Read(va.caChainURL)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no CA chain data returned from OpenBao")
	}

	if chainData, ok := secret.Data["certificate"].(string); ok {
		return []byte(chainData), nil
	}

	return nil, fmt.Errorf("CA chain not found in response")
}

func (va *openbaoPKIAgent) GetCRL() ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	secret, err := va.client.Logical().Read(va.crlURL)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no CRL data returned from OpenBao")
	}

	if crlData, ok := secret.Data["certificate"].(string); ok {
		return []byte(crlData), nil
	}

	return nil, fmt.Errorf("CRL not found in response")
}

func (va *openbaoPKIAgent) SignCSR(csr []byte, entityId, ttl string) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	secretValues := map[string]interface{}{
		"csr": string(csr),
		"ttl": ttl,
	}

	secret, err := va.client.Logical().Write(va.signURL, secretValues)
	if err != nil {
		return certs.Certificate{}, err
	}

	if secret == nil || secret.Data == nil {
		return certs.Certificate{}, fmt.Errorf("no certificate data returned from OpenBao")
	}

	cert := certs.Certificate{
		EntityID: entityId,
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
	}

	if serialNumber, ok := secret.Data["serial_number"].(string); ok {
		cert.SerialNumber = serialNumber
	}

	if expirationInterface, ok := secret.Data["expiration"]; ok {
		switch exp := expirationInterface.(type) {
		case int64:
			cert.ExpiryTime = time.Unix(exp, 0)
		case float64:
			cert.ExpiryTime = time.Unix(int64(exp), 0)
		case json.Number:
			if expInt, err := exp.Int64(); err == nil {
				cert.ExpiryTime = time.Unix(expInt, 0)
			}
		}
	}

	return cert, nil
}

func (va *openbaoPKIAgent) matchesCommonName(certPEM []byte, expectedCommonName string) bool {
	if len(certPEM) == 0 || expectedCommonName == "" {
		return false
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	return cert.Subject.CommonName == expectedCommonName
}
